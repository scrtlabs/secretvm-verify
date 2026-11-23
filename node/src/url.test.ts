import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { fetchGpuQuote, resolveServiceEndpointWithFallback } from "./url.js";

describe("evidence endpoint port fallback", () => {
  it("uses 29343 when the primary service answers", async (t) => {
    const urls: string[] = [];
    t.mock.method(globalThis, "fetch", async (url: any) => {
      urls.push(String(url));
      return new Response(String(url).endsWith("/cpu") ? "cpu" : "gpu evidence");
    });
    assert.equal(await fetchGpuQuote("node.example"), "gpu evidence");
    assert.deepEqual(urls, ["https://node.example:29343/cpu", "https://node.example:29343/gpu"]);
  });

  it("falls back to 21434 after a primary connection failure", async (t) => {
    const urls: string[] = [];
    t.mock.method(globalThis, "fetch", async (url: any) => {
      urls.push(String(url));
      if (String(url).includes(":29343/")) throw new Error("ECONNREFUSED");
      return new Response(String(url).endsWith("/cpu") ? "cpu" : "gpu evidence");
    });
    assert.equal(await fetchGpuQuote("node.example"), "gpu evidence");
    assert.deepEqual(urls, ["https://node.example:29343/cpu", "https://node.example:21434/cpu", "https://node.example:21434/gpu"]);
  });

  it("aborts a hanging primary probe after five seconds and falls back", async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let primarySignal: AbortSignal | undefined;
    t.mock.method(globalThis, "fetch", (url: any, init?: RequestInit) => {
      if (String(url).includes(":29343/")) {
        primarySignal = init?.signal ?? undefined;
        return new Promise<Response>((_resolve, reject) => {
          primarySignal!.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        });
      }
      return Promise.resolve(new Response(String(url).endsWith("/cpu") ? "cpu" : "gpu evidence"));
    });
    const result = fetchGpuQuote("node.example");
    t.mock.timers.tick(5000);
    assert.equal(await result, "gpu evidence");
    assert.equal(primarySignal?.aborted, true);
  });

  it("preserves a path prefix and IPv6 host through HTTP-error fallback", async (t) => {
    const urls: string[] = [];
    t.mock.method(globalThis, "fetch", async (url: any) => {
      urls.push(String(url));
      return new Response("evidence", { status: String(url).includes(":29343/") ? 503 : 200 });
    });
    assert.equal(await fetchGpuQuote("https://[::1]/teequote"), "evidence");
    assert.deepEqual(urls, ["https://[::1]:29343/teequote/cpu", "https://[::1]:21434/teequote/cpu", "https://[::1]:21434/teequote/gpu"]);
  });

  for (const port of [443, 29343, 21434, 12345]) {
    it(`honors explicit port ${port} without probing or fallback`, async (t) => {
      const urls: string[] = [];
      t.mock.method(globalThis, "fetch", async (url: any) => {
        urls.push(String(url));
        throw new Error("explicit port unavailable");
      });
      await assert.rejects(fetchGpuQuote(`https://node.example:${port}`), /explicit port unavailable/);
      assert.deepEqual(urls, [`https://node.example:${port}/gpu`]);
    });
  }

  it("does not switch services just because a reachable primary has no GPU", async (t) => {
    const urls: string[] = [];
    t.mock.method(globalThis, "fetch", async (url: any) => {
      urls.push(String(url));
      return new Response("", { status: String(url).endsWith("/cpu") ? 200 : 404 });
    });
    await assert.rejects(fetchGpuQuote("node.example"), /HTTP 404/);
    assert.deepEqual(urls, ["https://node.example:29343/cpu", "https://node.example:29343/gpu"]);
  });

  it("retains the primary endpoint for error reporting when neither service answers", async (t) => {
    const urls: string[] = [];
    t.mock.method(globalThis, "fetch", async (url: any) => {
      urls.push(String(url));
      return new Response("", { status: 503 });
    });
    await assert.rejects(fetchGpuQuote("node.example"), /HTTP 503 from https:\/\/node.example:29343\/gpu/);
    assert.equal(urls.length, 3);
  });

  it("rejects invalid service URLs before network access", async (t) => {
    const fetch = t.mock.method(globalThis, "fetch", async () => { throw new Error("unexpected fetch"); });
    for (const url of ["http://node.example", "https://u:p@node.example", "https://node.example/cpu", "https://node.example?x=1"]) {
      await assert.rejects(resolveServiceEndpointWithFallback(url));
    }
    assert.equal(fetch.mock.callCount(), 0);
  });
});
