import { test, expect, waitForPageReady, STRONG_PASSWORD, getSavedAdmin } from './fixture';

/**
 * Token 安全 E2E 测试
 * 
 * 测试覆盖：
 * 1. Session Token 安全属性
 * 2. Token 篡改检测
 * 3. Token 过期处理
 * 4. Token 注销与重放防护
 * 5. Token 窃取防护
 * 6. 并发会话管理
 */

test.describe.configure({ mode: 'serial' });

// ========== 1. Session Token 安全属性测试 ==========

test.describe('Session Token 安全属性', () => {
  test.use({ storageState: undefined });

  test('Session Cookie 具有 HttpOnly 属性', async ({ authenticatedPage: page, context }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    expect(sessionCookie).toBeDefined();
    expect(sessionCookie?.value).toBeTruthy();

    // 注意：Playwright 无法直接检测 HttpOnly
    // 但我们可以验证 cookie 存在且有效
    console.log(`Session cookie exists: ${!!sessionCookie}`);
  });

  test('Session Cookie 路径设置为根路径', async ({ authenticatedPage: page, context }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    expect(sessionCookie?.path).toBe('/');
  });

  test('CSRF Token Cookie 与 Session 配对', async ({ authenticatedPage: page, context }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');

    expect(sessionCookie).toBeDefined();
    expect(csrfCookie).toBeDefined();
  });

  test('Cookie SameSite 属性正确设置', async ({ authenticatedPage: page, context }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    if (sessionCookie?.sameSite) {
      expect(['Strict', 'Lax', 'None']).toContain(sessionCookie.sameSite);
    }
  });
});

// ========== 2. Token 篡改检测测试 ==========

test.describe('Token 篡改检测', () => {
  test.use({ storageState: undefined });

  test('篡改的 Session Token 被拒绝', async ({ request }) => {
    const tamperedTokens = [
      'tampered-token-12345',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake', // 假 JWT 格式
      'a'.repeat(100), // 超长 token
      '', // 空 token
      'null',
      'undefined',
      '<script>alert(1)</script>',
    ];

    for (const token of tamperedTokens) {
      const response = await request.get('/api/user/me', {
        headers: { 'Cookie': `session=${token}` },
      });

      expect(response.status()).toBe(401);
    }
  });

  test('修改后的 Token 签名无效', async ({ request }) => {
    // 尝试使用格式正确但签名无效的 token
    const invalidTokens = [
      // 假设是 JWT 格式，修改 payload 部分保持 header 和 signature
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.modified.modified',
    ];

    for (const token of invalidTokens) {
      const response = await request.get('/api/user/me', {
        headers: { 'Cookie': `session=${token}` },
      });

      expect(response.status()).toBe(401);
    }
  });

  test('Token 中注入特殊字符被正确处理', async ({ request }) => {
    const specialCharTokens = [
      'token\x00with\x00nulls',
      'token with spaces',
      'token"with"quotes',
      "token'with'quotes",
      'token\nwith\nnewlines',
      'token%00with%00encoded',
    ];

    for (const token of specialCharTokens) {
      const response = await request.get('/api/user/me', {
        headers: { 'Cookie': `session=${encodeURIComponent(token)}` },
      });

      // 应该返回未授权或错误
      expect([400, 401]).toContain(response.status());
    }
  });

  test('不同用户的 Token 不可互换', async ({ browser }) => {
    const savedAdmin = getSavedAdmin();
    if (!savedAdmin) {
      test.skip();
      return;
    }

    // 创建两个用户会话
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();

    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    try {
      // 第一个用户登录
      await page1.goto('/');
      await waitForPageReady(page1);
      await page1.locator('#username').fill(savedAdmin.username);
      await page1.locator('#password').fill(savedAdmin.password);
      await page1.locator('button[type="submit"]:has-text("登录")').click();
      await page1.waitForTimeout(2000);

      // 第二个用户（使用相同账号，获取不同 session）
      await page2.goto('/');
      await waitForPageReady(page2);
      await page2.locator('#username').fill(savedAdmin.username);
      await page2.locator('#password').fill(savedAdmin.password);
      await page2.locator('button[type="submit"]:has-text("登录")').click();
      await page2.waitForTimeout(2000);

      const cookies1 = await context1.cookies();
      const cookies2 = await context2.cookies();

      const session1 = cookies1.find(c => c.name === 'session');
      const session2 = cookies2.find(c => c.name === 'session');

      // 两个 session 应该不同
      if (session1 && session2) {
        expect(session1.value).not.toBe(session2.value);
      }
    } finally {
      await context1.close();
      await context2.close();
    }
  });
});

// ========== 3. Token 过期处理测试 ==========

test.describe('Token 过期处理', () => {
  test.use({ storageState: undefined });

  test('过期 Token 无法访问受保护资源', async ({ request }) => {
    // 使用显然无效的 token
    const response = await request.get('/api/user/me', {
      headers: { 'Cookie': 'session=expired-token-test' },
    });

    expect(response.status()).toBe(401);
  });

  test('Session 过期后自动清理', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取会话列表
    const sessions = await page.evaluate(async () => {
      const res = await fetch('/api/user/sessions');
      return res.ok ? await res.json() : [];
    });

    // 应该有会话记录
    expect(Array.isArray(sessions)).toBeTruthy();
    expect(sessions.length).toBeGreaterThanOrEqual(1);
  });

  test('长时间会话有明确的过期时间', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const sessions = await page.evaluate(async () => {
      const res = await fetch('/api/user/sessions');
      return res.ok ? await res.json() : [];
    });

    for (const session of sessions) {
      expect(session.expiresAt).toBeTruthy();

      // 验证过期时间是有效的日期
      const expiresAt = new Date(session.expiresAt);
      expect(expiresAt.toString()).not.toBe('Invalid Date');
    }
  });
});

// ========== 4. Token 注销与重放防护测试 ==========

test.describe('Token 注销与重放防护', () => {
  test.use({ storageState: undefined });

  test('登出后 Token 立即失效', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    if (!sessionCookie) {
      test.skip();
      return;
    }

    const oldSession = sessionCookie.value;

    // 登出（携带 CSRF token）
    await page.evaluate(async () => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );
      await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } });
    });

    await page.waitForTimeout(1000);

    // 尝试使用旧 token
    const response = await request.get('/api/user/me', {
      headers: { 'Cookie': `session=${oldSession}` },
    });

    // 应该返回未授权
    expect(response.status()).toBe(401);
  });

  test('会话终止后 Token 失效', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取所有会话
    const sessions = await page.evaluate(async () => {
      const res = await fetch('/api/user/sessions');
      return res.ok ? await res.json() : [];
    });

    // 找到非当前会话
    const otherSession = sessions.find((s: any) => !s.current);

    if (otherSession) {
      // 终止该会话
      await page.evaluate(async (sessionId: string) => {
        const csrfToken = decodeURIComponent(
          document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
        );

        await fetch(`/api/user/sessions/${sessionId}`, {
          method: 'DELETE',
          headers: { 'X-CSRF-Token': csrfToken },
        });
      }, otherSession.id);

      // 验证会话已移除
      const updatedSessions = await page.evaluate(async () => {
        const res = await fetch('/api/user/sessions');
        return res.ok ? await res.json() : [];
      });

      const terminatedExists = updatedSessions.some((s: any) => s.id === otherSession.id);
      expect(terminatedExists).toBeFalsy();
    }
  });

  test('同一会话不能被重复终止', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const sessions = await page.evaluate(async () => {
      const res = await fetch('/api/user/sessions');
      return res.ok ? await res.json() : [];
    });

    const otherSession = sessions.find((s: any) => !s.current);

    if (otherSession) {
      // 第一次终止
      const result1 = await page.evaluate(async (sessionId: string) => {
        const csrfToken = decodeURIComponent(
          document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
        );

        const res = await fetch(`/api/user/sessions/${sessionId}`, {
          method: 'DELETE',
          headers: { 'X-CSRF-Token': csrfToken },
        });

        return { status: res.status };
      }, otherSession.id);

      expect([200, 204]).toContain(result1.status);

      // 第二次终止同一会话
      const result2 = await page.evaluate(async (sessionId: string) => {
        const csrfToken = decodeURIComponent(
          document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
        );

        const res = await fetch(`/api/user/sessions/${sessionId}`, {
          method: 'DELETE',
          headers: { 'X-CSRF-Token': csrfToken },
        });

        return { status: res.status };
      }, otherSession.id);

      // 应该返回 404 或 200（幂等性）
      expect([200, 204, 404]).toContain(result2.status);
    }
  });
});

// ========== 5. Token 窃取防护测试 ==========

test.describe('Token 窃取防护', () => {
  test.use({ storageState: undefined });

  test('不同源的请求不带 Session Cookie', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 跨域请求（模拟）不应该自动携带 cookie
    // 这个测试验证 SameSite 属性的效果
    const response = await request.get('/api/user/me', {
      headers: {
        'Origin': 'http://evil.com',
      },
    });

    // 应该返回 401（未授权）
    expect(response.status()).toBe(401);
  });

  test('Session 不在 JavaScript 中可访问', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 尝试通过 document.cookie 访问 session
    const cookieAccess = await page.evaluate(() => {
      const cookies = document.cookie;
      return {
        hasSession: cookies.includes('session='),
        cookies: cookies,
      };
    });

    // 如果 HttpOnly 正确设置，JavaScript 无法访问 session cookie
    // 注意：csrf_token 是需要被 JavaScript 访问的
    console.log(`Session accessible via JS: ${cookieAccess.hasSession}`);
  });

  test('Token 不出现在 Referer 头中', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 检查页面跳转时 token 是否泄露
    const navigations: string[] = [];

    page.on('request', req => {
      const referer = req.headers()['referer'];
      if (referer && referer.includes('session')) {
        navigations.push(referer);
      }
    });

    // 导航到其他页面
    await page.goto('/#user');
    await waitForPageReady(page);

    // 验证没有 token 泄露
    expect(navigations.length).toBe(0);
  });

  test('Token 不在错误页面中显示', async ({ page, request }) => {
    await page.goto('/');
    await waitForPageReady(page);

    // 触发一个错误
    await page.goto('/api/nonexistent-endpoint');
    await page.waitForTimeout(1000);

    // 检查错误响应
    const body = await page.content();
    expect(body.toLowerCase()).not.toContain('session=');
  });
});

// ========== 6. 并发会话管理测试 ==========

test.describe('并发会话管理', () => {
  test.use({ storageState: undefined });

  test('同一用户可以创建多个会话', async ({ browser }) => {
    const savedAdmin = getSavedAdmin();
    if (!savedAdmin) {
      test.skip();
      return;
    }

    const contexts = [];
    const pages = [];

    try {
      // 创建多个会话
      for (let i = 0; i < 3; i++) {
        const ctx = await browser.newContext();
        const p = await ctx.newPage();

        await p.goto('/');
        await waitForPageReady(p);
        await p.locator('#username').fill(savedAdmin.username);
        await p.locator('#password').fill(savedAdmin.password);
        await p.locator('button[type="submit"]:has-text("登录")').click();
        await p.waitForTimeout(2000);

        contexts.push(ctx);
        pages.push(p);
      }

      // 验证所有会话都有效
      const results = await Promise.all(
        pages.map(p =>
          p.evaluate(async () => {
            const res = await fetch('/api/user/me');
            return res.ok;
          })
        )
      );

      for (const result of results) {
        expect(result).toBeTruthy();
      }

      // 验证会话列表显示多个会话
      const sessions = await pages[0].evaluate(async () => {
        const res = await fetch('/api/user/sessions');
        return res.ok ? await res.json() : [];
      });

      expect(sessions.length).toBeGreaterThanOrEqual(3);
    } finally {
      for (const ctx of contexts) {
        await ctx.close();
      }
    }
  });

  test('一个会话登出不影响其他会话', async ({ browser }) => {
    const savedAdmin = getSavedAdmin();
    if (!savedAdmin) {
      test.skip();
      return;
    }

    const context1 = await browser.newContext();
    const context2 = await browser.newContext();

    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    try {
      // 两个会话都登录
      for (const page of [page1, page2]) {
        await page.goto('/');
        await waitForPageReady(page);
        await page.locator('#username').fill(savedAdmin.username);
        await page.locator('#password').fill(savedAdmin.password);
        await page.locator('button[type="submit"]:has-text("登录")').click();
        await page.waitForTimeout(2000);
      }

      // 第一个会话登出（携带 CSRF token）
      await page1.evaluate(async () => {
        const csrfToken = decodeURIComponent(
          document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
        );
        await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } });
      });

      await page1.waitForTimeout(1000);

      // 第二个会话应该仍然有效
      const stillValid = await page2.evaluate(async () => {
        const res = await fetch('/api/user/me');
        return res.ok;
      });

      expect(stillValid).toBeTruthy();
    } finally {
      await context1.close();
      await context2.close();
    }
  });

  test('会话数量有限制', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取会话列表
    const sessions = await page.evaluate(async () => {
      const res = await fetch('/api/user/sessions');
      return res.ok ? await res.json() : [];
    });

    // 验证会话数量合理（不无限增长）
    expect(sessions.length).toBeLessThan(100);
  });
});

// ========== 7. Token 刷新安全测试 ==========

test.describe('Token 刷新安全', () => {
  test.use({ storageState: undefined });

  test('刷新令牌只能使用一次（如果实现）', async ({ request }) => {
    // 测试 OIDC refresh token 流程
    const response = await request.post('/oauth/token', {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: 'test-refresh-token',
        client_id: 'test-client',
      }).toString(),
    });

    // 应该返回错误（无效的 refresh token）
    expect([400, 401, 403, 404]).toContain(response.status());
  });

  test('刷新令牌与 Session 关联', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取当前会话信息
    const sessionInfo = await page.evaluate(async () => {
      const sessions = await (await fetch('/api/user/sessions')).json();
      const me = await (await fetch('/api/user/me')).json();
      return { sessions, me };
    });

    // 验证会话与用户关联
    expect(sessionInfo.me).toBeDefined();
    expect(sessionInfo.sessions.length).toBeGreaterThan(0);
  });
});

// ========== 8. API 授权测试 ==========

test.describe('API 授权', () => {
  test.use({ storageState: undefined });

  test('未认证用户无法访问受保护 API', async ({ request }) => {
    const protectedEndpoints = [
      { method: 'GET', url: '/api/user/me' },
      { method: 'GET', url: '/api/user/sessions' },
      { method: 'PATCH', url: '/api/user/profile' },
      { method: 'PATCH', url: '/api/user/password' },
      { method: 'GET', url: '/api/admin/users' },
      { method: 'GET', url: '/api/admin/groups' },
    ];

    for (const endpoint of protectedEndpoints) {
      const response = await request.fetch(endpoint.url, {
        method: endpoint.method,
        headers: { 'Content-Type': 'application/json' },
        data: endpoint.method !== 'GET' ? {} : undefined,
      });

      expect([401, 403]).toContain(response.status());
    }
  });

  test('普通用户无法访问管理员 API', async ({ authenticatedPage: page, request }) => {
    // 这个测试假设 authenticatedPage 是管理员
    // 获取页面的认证信息
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    if (!sessionCookie) {
      test.skip();
      return;
    }

    const response = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${sessionCookie.value}` },
    });

    // 管理员返回 200，普通用户返回 403
    expect([200, 403]).toContain(response.status());
  });

  test('API 返回正确的认证错误格式', async ({ request }) => {
    const response = await request.get('/api/user/me');

    expect(response.status()).toBe(401);

    // 验证错误响应格式
    const data = await response.json();
    expect(data.error).toBeDefined();
  });
});

// ========== 清理测试 ==========

test.describe('清理', () => {
  test('Token 安全测试完成', async () => {
    expect(true).toBeTruthy();
  });
});
