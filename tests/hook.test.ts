import { describe, expect, it } from 'vitest';
import {
  commandFetch,
  compactSession,
  decisionLog,
  decisionLogLines,
  getApiKey,
  register,
  resolveHookConfig,
  summarize,
  toSessionMessages,
} from '../hooks/fast-jev.ts';
import { applyDecisions, collectToolCalls, decideCall, type Message } from '../src/index.js';

type SessionMessage = Message & { handle?: string };

function message(role: Message['role'], text: string, extra: Partial<SessionMessage> = {}): SessionMessage {
  return { role, text, toolUses: [], ...extra };
}

function call(id: string, tool: string, input: Record<string, unknown>, text: string): SessionMessage {
  return message('assistant', '', {
    toolUses: [{ tool_use_id: id, tool, input, text }],
    handle: `h-${id}`,
  });
}

function result(id: string, text: string, isError = false): SessionMessage {
  return message('user', '', { toolResults: [{ tool_use_id: id, text, isError }], handle: `r-${id}` });
}

const fileA = 'export const a = 1;\n'.repeat(50);

function transcript(): SessionMessage[] {
  return [
    message('user', 'Fix the failing test.', { handle: 'h-0' }),
    call('tool-1', 'Read', { file_path: 'src/a.ts' }, fileA),
    result('tool-1', fileA),
    call('tool-2', 'Bash', { command: 'npm test' }, 'FAIL'),
    result('tool-2', 'FAIL b.test.ts: expected 2 to be 3', true),
    message('assistant', 'Fixing now.', { handle: 'h-5' }),
    message('user', 'go ahead', { handle: 'h-6' }),
  ];
}

function jevFetch(answer: (name: string) => number, bodies: string[] = []) {
  return async (_url: string, init?: { body?: string }) => {
    bodies.push(init?.body ?? '');
    const { questions } = JSON.parse(init?.body ?? '{}') as { questions: Record<string, unknown> };
    const answers = Object.fromEntries(
      Object.keys(questions).map((key) => [key, { type: 'noul', noul: answer(key) }]),
    );
    return { status: 200, ok: true, text: JSON.stringify({ answers }) };
  };
}

describe('hook config', () => {
  it('reads userConfig values and falls back to defaults', () => {
    expect(resolveHookConfig({})).toEqual({ compactAtPercent: 60, minReductionRatio: 0.25, model: 'jev-latest' });
    expect(
      resolveHookConfig({ apiKey: 'k', keepThreshold: 0.3, maxStateTokens: 1000, model: 'jev-x', goal: 'g', compactAtPercent: 'no', fetchCommand: 'f' }),
    ).toEqual({
      apiKey: 'k',
      fetchCommand: 'f',
      keepThreshold: 0.3,
      maxStateTokens: 1000,
      model: 'jev-x',
      goal: 'g',
      compactAtPercent: 60,
      minReductionRatio: 0.25,
    });
  });
});

describe('session message mapping', () => {
  it('returns the engine objects for untouched messages and handle-less copies for rebuilt ones', () => {
    const messages = transcript();
    const calls = collectToolCalls(messages, 0);
    const decisions = [
      decideCall(calls[0]!, { keepCall: 0.9, keepResult: 0.1 }, { keepThreshold: 0.5 }),
      decideCall(calls[1]!, { keepCall: 0.9, keepResult: 0.9 }, { keepThreshold: 0.5 }),
    ];
    messages[1]!.toolUses[0]!.text = 'x'.repeat(2000);
    messages[2]!.toolResults![0]!.text = 'x'.repeat(2000);
    const out = toSessionMessages(messages, applyDecisions(messages, decisions, calls, 300));
    expect(out).toHaveLength(messages.length);
    expect(out[0]).toBe(messages[0]);
    expect(out[1]?.handle).toBeUndefined();
    expect(out[1]?.toolUses[0]?.text).toMatch(
      new RegExp(`^${'x'.repeat(300)}\\n\\[fast-jev-compaction truncated 1700 chars`),
    );
    expect(out[2]?.handle).toBeUndefined();
    expect(out[2]?.toolResults?.[0]?.text).toMatch(
      new RegExp(`^${'x'.repeat(300)}\\n\\[fast-jev-compaction truncated 1700 chars`),
    );
    expect(out[2]?.toolResults?.[0]).toMatchObject({ tool_use_id: 'tool-1', isError: false });
    expect(out[3]).toBe(messages[3]);
    expect(out[4]).toBe(messages[4]);
  });

  it('preserves short dropped-result messages and their handles', () => {
    const messages = transcript();
    messages[1]!.toolUses[0]!.text = 'y'.repeat(100);
    messages[2]!.toolResults![0]!.text = 'y'.repeat(100);
    const calls = collectToolCalls(messages, 0);
    const decisions = [
      decideCall(calls[0]!, { keepCall: 0.9, keepResult: 0.1 }, { keepThreshold: 0.5 }),
      decideCall(calls[1]!, { keepCall: 0.9, keepResult: 0.9 }, { keepThreshold: 0.5 }),
    ];
    const out = toSessionMessages(messages, applyDecisions(messages, decisions, calls, 300));
    expect(out[1]).toBe(messages[1]);
    expect(out[2]).toBe(messages[2]);
  });
});

describe('compactSession', () => {
  it('runs the library over the engine fetch and reports the outcome', async () => {
    const bodies: string[] = [];
    const config = { ...resolveHookConfig({ preserveRecentMessages: 1 }), apiKey: 'k', model: 'jev-x' };
    const { result: output, messages } = await compactSession(
      transcript(),
      config,
      jevFetch((name) => (name === 'call_t2' || name === 'result_t2' ? 0.9 : 0.1), bodies),
    );
    expect(bodies).toHaveLength(1);
    expect(JSON.parse(bodies[0]!).model).toBe('jev-x');
    expect(output.decisions.map((d) => d.action)).toEqual(['drop_call', 'keep']);
    expect(messages.map((m) => m.handle)).toEqual(['h-0', 'h-tool-2', 'r-tool-2', 'h-5', 'h-6']);
    expect(summarize(output)).toMatch(/^\d+% reduction; 1 kept, 1 call_dropped; state ~\d+ tokens \(full\) in 1 request\(s\)$/);
    expect(decisionLog(output)).toBe('t1:Read:drop_call/call=0.10/result=0.10 t2:Bash:keep/call=0.90/result=0.90');
    expect(decisionLogLines(output)).toEqual([`decisions: ${decisionLog(output)}`]);
  });

  it('splits a long decision log into ui.log lines under the host limit', async () => {
    const config = { ...resolveHookConfig({ preserveRecentMessages: 1 }), apiKey: 'k' };
    const { result: output } = await compactSession(transcript(), config, jevFetch(() => 0.1));
    const lines = decisionLogLines(output, 60);
    expect(lines).toEqual([
      'decisions (1/2): t1:Read:drop_call/call=0.10/result=0.10',
      'decisions (2/2): t2:Bash:drop_call/call=0.10/result=0.10',
    ]);
    expect(lines.every((line) => line.length <= 60)).toBe(true);
    expect(decisionLogLines({ ...output, decisions: [] })).toEqual(['decisions: (none)']);
  });

  it('throws on a missing key and on failed requests so the hook falls back', async () => {
    const config = resolveHookConfig({ preserveRecentMessages: 1 });
    await expect(compactSession(transcript(), config, jevFetch(() => 0))).rejects.toThrow(/TYPESAFE_API_KEY/);
    await expect(
      compactSession(transcript(), { ...config, apiKey: 'k' }, async () => ({ status: 500, ok: false, text: 'x' })),
    ).rejects.toThrow(/500/);
  });
});

describe('session.compact hook', () => {
  type Compact = (
    $: unknown,
    event: { trigger: string; messages: SessionMessage[] },
    next: () => Promise<unknown>,
  ) => Promise<unknown>;

  function compactHook(options: Record<string, unknown>): Compact {
    let hook: Compact | undefined;
    const on = (name: string, ...rest: unknown[]) => {
      if (name === 'session.compact') hook = rest[rest.length - 1] as Compact;
    };
    register(on as never, options as never);
    return hook!;
  }

  function host(fetch: ReturnType<typeof jevFetch>, toasts: string[]) {
    return {
      env: { get: async () => undefined },
      settings: { read: async () => ({}) },
      http: { fetch },
      ui: { log: () => {}, toast: (text: string) => toasts.push(text) },
    };
  }

  const next = async () => ({ skip: 'built-in' });

  it('skips a precompute without asking Jev', async () => {
    const bodies: string[] = [];
    const out = await compactHook({ apiKey: 'k', preserveRecentMessages: 1 })(
      host(jevFetch(() => 0.1, bodies), []),
      { trigger: 'precompute', messages: transcript() },
      next,
    );
    expect(out).toEqual({ skip: expect.stringMatching(/precompute/) });
    expect(bodies).toHaveLength(0);
  });

  it('hands a precompute to the built-in summary when no drop reaches the minimum', async () => {
    const bodies: string[] = [];
    const out = await compactHook({ apiKey: 'k' })(
      host(jevFetch(() => 0.1, bodies), []),
      { trigger: 'precompute', messages: transcript() },
      next,
    );
    expect(out).toEqual({ skip: 'built-in' });
    expect(bodies).toHaveLength(0);
  });

  it('names the trigger in the toast', async () => {
    const toasts: string[] = [];
    await compactHook({ apiKey: 'k', preserveRecentMessages: 1 })(
      host(jevFetch(() => 0.1), toasts),
      { trigger: 'auto', messages: transcript() },
      next,
    );
    await compactHook({})(host(jevFetch(() => 0.1), toasts), { trigger: 'manual', messages: transcript() }, next);
    expect(toasts).toEqual([
      expect.stringMatching(/^kept 3\/7 messages \(auto\), no summary \(/),
      'fallback to built-in summary (manual; TYPESAFE_API_KEY is not configured)',
    ]);
  });

  it('sends Jev requests through fetchCommand when it is set', async () => {
    const bodies: string[] = [];
    const answer = jevFetch(() => 0.1, bodies);
    const notFetch = (async () => {
      throw new Error('$.http.fetch must not run');
    }) as ReturnType<typeof jevFetch>;
    const toasts: string[] = [];
    const $ = {
      ...host(notFetch, toasts),
      process: {
        run: async (_argv: readonly string[], init?: { stdin?: string }) => {
          const { url, ...rest } = JSON.parse(init?.stdin ?? '{}') as { url: string; body?: string };
          const response = await answer(url, rest);
          return { exitCode: 0, stdout: JSON.stringify({ status: response.status, text: response.text }), stderr: '' };
        },
      },
    };
    await compactHook({ apiKey: 'k', preserveRecentMessages: 1, fetchCommand: 'node jev-fetch.mjs' })(
      $,
      { trigger: 'auto', messages: transcript() },
      next,
    );
    expect(bodies).not.toHaveLength(0);
    expect(toasts).toEqual([expect.stringMatching(/^kept 3\/7 messages \(auto\)/)]);
  });

  it('takes fetchCommand from FAST_JEV_FETCH_COMMAND when the option is unset', async () => {
    const bodies: string[] = [];
    const answer = jevFetch(() => 0.1, bodies);
    const notFetch = (async () => {
      throw new Error('$.http.fetch must not run');
    }) as ReturnType<typeof jevFetch>;
    const commands: string[] = [];
    const toasts: string[] = [];
    const $ = {
      ...host(notFetch, toasts),
      env: { get: async (name: string) => (name === 'FAST_JEV_FETCH_COMMAND' ? 'node from-env.mjs' : undefined) },
      process: {
        run: async (argv: readonly string[], init?: { stdin?: string }) => {
          commands.push(argv[argv.length - 1]!);
          const { url, ...rest } = JSON.parse(init?.stdin ?? '{}') as { url: string; body?: string };
          const response = await answer(url, rest);
          return { exitCode: 0, stdout: JSON.stringify({ status: response.status, text: response.text }), stderr: '' };
        },
      },
    };
    await compactHook({ apiKey: 'k', preserveRecentMessages: 1 })($, { trigger: 'auto', messages: transcript() }, next);
    expect(bodies).not.toHaveLength(0);
    expect(new Set(commands)).toEqual(new Set(['node from-env.mjs']));
    expect(toasts).toEqual([expect.stringMatching(/^kept 3\/7 messages \(auto\)/)]);
  });
});

describe('commandFetch', () => {
  const command = 'node ~/jev-fetch.mjs';
  const url = 'https://api.typesafe.ai/v1/systemone';

  it('runs the command through sh with the request as JSON on stdin', async () => {
    const calls: unknown[] = [];
    const fetch = commandFetch(
      async (argv, init) => {
        calls.push({ argv, init });
        return { exitCode: 0, stdout: '{"status":200,"text":"{}"}', stderr: '' };
      },
      command,
      '/home/me',
    );
    const init = { method: 'POST', headers: { authorization: 'Bearer k' }, body: '{}' };
    expect(await fetch(url, init)).toEqual({ status: 200, ok: true, text: '{}' });
    expect(calls).toEqual([
      {
        argv: ['/bin/sh', '-c', command],
        init: { cwd: '/home/me', stdin: JSON.stringify({ url, ...init }), timeoutMs: 60_000 },
      },
    ]);
  });

  it('fails on a nonzero exit, with stderr, and on output that is not { status, text }', async () => {
    const refused = 'jev-fetch: refused api.typesafe.ai: the certificate name does not match\n';
    await expect(
      commandFetch(async () => ({ exitCode: 1, stdout: '', stderr: refused }), command, undefined)(url),
    ).rejects.toThrow(`fetchCommand exited 1: ${refused.trim()}`);
    await expect(
      commandFetch(async () => ({ exitCode: 0, stdout: 'oops', stderr: '' }), command, undefined)(url),
    ).rejects.toThrow('fetchCommand printed no { status, text } JSON');
  });
});

describe('getApiKey', () => {
  const command = 'infisical secrets get TYPESAFE_API_KEY --plain';

  function host(run: (argv: readonly string[], init?: { cwd?: string }) => Promise<{ exitCode: number | null; stdout: string }>) {
    return {
      env: { get: async (name: string) => (name === 'HOME' ? '/home/me' : undefined) },
      settings: { read: async () => ({}) },
      process: { run },
    };
  }

  const mustNotRun = async () => {
    throw new Error('apiKeyCommand must not run');
  };

  it('prefers the option and the environment over apiKeyCommand', async () => {
    const config = resolveHookConfig({ apiKey: 'opt', apiKeyCommand: command });
    expect(await getApiKey(host(mustNotRun), config)).toBe('opt');
    const $ = { ...host(mustNotRun), env: { get: async (name: string) => (name === 'TYPESAFE_API_KEY' ? 'env' : undefined) } };
    expect(await getApiKey($, resolveHookConfig({ apiKeyCommand: command }))).toBe('env');
  });

  it('runs apiKeyCommand through sh from HOME', async () => {
    const calls: { argv: readonly string[]; cwd?: string }[] = [];
    const key = await getApiKey(
      host(async (argv, init) => {
        calls.push({ argv, cwd: init?.cwd });
        return { exitCode: 0, stdout: 'secret\n' };
      }),
      resolveHookConfig({ apiKeyCommand: command }),
    );
    expect(key).toBe('secret');
    expect(calls).toEqual([{ argv: ['/bin/sh', '-c', command], cwd: '/home/me' }]);
  });

  it('is undefined without apiKeyCommand, or when the command fails', async () => {
    expect(await getApiKey(host(mustNotRun), resolveHookConfig({}))).toBeUndefined();
    const config = resolveHookConfig({ apiKeyCommand: command });
    expect(await getApiKey(host(async () => ({ exitCode: 1, stdout: '' })), config)).toBeUndefined();
    expect(
      await getApiKey(
        host(async () => {
          throw new Error('ENOENT');
        }),
        config,
      ),
    ).toBeUndefined();
  });
});
