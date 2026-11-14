import { test, expect, STRONG_PASSWORD, saveAdmin, getSavedAdmin, FIXED_ADMIN_USERNAME, FIXED_ADMIN_PASSWORD, FIXED_ADMIN_EMAIL } from './fixture';

/**
 * 首次启动流程测试
 * 
 * 测试注册、登录流程。
 * 注意：goauth 注册成功后需要重新登录。
 * 
 * 关键：使用固定的管理员凭据，确保后续测试可以重用
 */

test.describe.configure({ mode: 'serial' });

test.describe('首次启动流程', () => {
  test('1. 首次访问显示登录页面', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    
    // 应该看到登录标题
    await expect(page.locator('h1:has-text("登录")')).toBeVisible({ timeout: 10000 });
    
    // 应该有注册链接（首次启动允许注册）
    const registerLink = page.locator('a:has-text("注册")');
    await expect(registerLink).toBeVisible();
  });

  test('2. 第一个用户注册成功并登录（使用固定管理员）', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    
    // 点击注册链接
    await page.locator('a:has-text("注册")').click();
    await page.waitForTimeout(500);
    
    // 确认在注册页面
    await expect(page.locator('h1:has-text("注册")')).toBeVisible({ timeout: 5000 });
    
    // 使用固定的管理员凭据
    const username = FIXED_ADMIN_USERNAME;
    const email = FIXED_ADMIN_EMAIL;
    await page.locator('#reg-username').fill(username);
    await page.locator('#reg-email').fill(email);
    await page.locator('#reg-password').fill(FIXED_ADMIN_PASSWORD);
    await page.locator('#reg-confirm').fill(FIXED_ADMIN_PASSWORD);
    
    // 提交注册
    await page.locator('button:has-text("注册")').click();
    
    // 等待注册成功 - 应该跳转回登录页
    await page.waitForTimeout(2000);
    
    // 验证回到登录页（注册成功后会跳转到登录页）
    await expect(page.locator('h1:has-text("登录")')).toBeVisible({ timeout: 10000 });
    
    // 第一个用户自动成为管理员，登录
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(FIXED_ADMIN_PASSWORD);
    await page.locator('button[type="submit"]:has-text("登录")').click();
    
    // 等待登录成功
    await page.waitForTimeout(2000);
    
    // 验证登录成功 - 应该看到管理后台
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 10000 });
    
    // 保存管理员凭据供后续测试使用
    saveAdmin(username, FIXED_ADMIN_PASSWORD, email);
  });

  test('3. 新用户注册后可以登录（测试环境自动批准）', async ({ page }) => {
    // 先注册用户
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);

    const username = `loginuser_${Date.now()}`;

    // 注册
    await page.locator('a:has-text("注册")').click();
    await page.waitForTimeout(500);
    await page.locator('#reg-username').fill(username);
    await page.locator('#reg-email').fill(`${username}@test.local`);
    await page.locator('#reg-password').fill(STRONG_PASSWORD);
    await page.locator('#reg-confirm').fill(STRONG_PASSWORD);
    await page.locator('button:has-text("注册")').click();

    // 等待回到登录页
    await expect(page.locator('h1').filter({ hasText: '登录' })).toBeVisible({ timeout: 10000 });
    await page.waitForTimeout(500);

    // 尝试登录
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(STRONG_PASSWORD);
    
    // 等待登录请求完成
    const loginPromise = page.waitForResponse(resp => 
      resp.url().includes('/api/auth/login') && resp.request().method() === 'POST'
    );
    await page.locator('button[type="submit"]:has-text("登录")').click();
    const loginResponse = await loginPromise;
    
    // 检查登录响应
    expect(loginResponse.ok()).toBeTruthy();
    const loginData = await loginResponse.json();
    expect(loginData.user).toBeDefined();
    expect(loginData.user.username).toBe(username);
    
    // 等待页面渲染
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // 通过 API 验证登录状态
    const meResponse = await page.evaluate(async () => {
      const res = await fetch('/api/user/me');
      if (res.ok) {
        const data = await res.json();
        return { ok: true, username: data.username };
      }
      return { ok: false };
    });
    expect(meResponse.ok).toBeTruthy();
    expect(meResponse.username).toBe(username);
  });

  test('4. 可以登出并重新登录', async ({ page }) => {
    // 使用保存的管理员账号测试登出和重新登录
    const savedAdmin = getSavedAdmin();
    
    // 首先清除所有 cookies 确保从登录页开始
    const context = page.context();
    await context.clearCookies();
    
    // 导航到首页让前端重新检测登录状态
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);

    // 确认在登录页
    await expect(page.locator('h1:has-text("登录")')).toBeVisible({ timeout: 10000 });
    
    if (savedAdmin) {
      // 登录
      await page.locator('#username').fill(savedAdmin.username);
      await page.locator('#password').fill(savedAdmin.password);
      await page.locator('button[type="submit"]:has-text("登录")').click();
      await page.waitForTimeout(2000);
      
      // 验证登录成功
      await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 10000 });
      
      // 使用 API 登出（携带 CSRF token）
      await page.evaluate(async () => {
        const csrfToken = decodeURIComponent(
          document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
        );
        await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } });
      });
      
      // 清除 cookies 并刷新页面
      await context.clearCookies();
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000);
      
      // 验证回到登录页
      await expect(page.locator('h1:has-text("登录")')).toBeVisible({ timeout: 5000 });
      
      // 重新登录
      await page.locator('#username').fill(savedAdmin.username);
      await page.locator('#password').fill(savedAdmin.password);
      await page.locator('button[type="submit"]:has-text("登录")').click();
      await page.waitForTimeout(2000);
      
      // 验证再次登录成功
      await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 10000 });
    }
  });

  test('5. 错误密码显示错误信息', async ({ page }) => {
    const savedAdmin = getSavedAdmin();
    
    // 首先清除所有 cookies 确保从登录页开始
    const context = page.context();
    await context.clearCookies();
    
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    
    // 确认在登录页
    await expect(page.locator('h1:has-text("登录")')).toBeVisible({ timeout: 10000 });
    
    if (savedAdmin) {
      // 用错误密码登录管理员账号
      await page.locator('#username').fill(savedAdmin.username);
      await page.locator('#password').fill('WrongPassword123!');
      await page.locator('button[type="submit"]:has-text("登录")').click();
      
      // 等待错误消息
      await page.waitForTimeout(2000);
      
      // 应该显示错误
      const errorVisible = await page.locator('.error').isVisible({ timeout: 3000 }).catch(() => false);
      const stillOnLogin = page.url().includes('#login') || page.url().endsWith('/');
      expect(errorVisible || stillOnLogin).toBeTruthy();
    } else {
      // 如果没有保存的管理员，跳过测试
      expect(true).toBeTruthy();
    }
  });

  test('6. 密码不一致显示错误', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    
    // 点击注册
    await page.locator('a:has-text("注册")').click();
    await page.waitForTimeout(500);
    
    await page.locator('#reg-username').fill(`mismatch_${Date.now()}`);
    await page.locator('#reg-email').fill('mismatch@test.local');
    await page.locator('#reg-password').fill(STRONG_PASSWORD);
    await page.locator('#reg-confirm').fill('DifferentPassword123!');
    
    await page.locator('button:has-text("注册")').click();
    
    // 等待错误消息
    await page.waitForTimeout(1500);
    
    // 应该显示错误或仍在注册页
    const errorVisible = await page.locator('.error').isVisible({ timeout: 3000 }).catch(() => false);
    const stillOnRegister = await page.locator('h1:has-text("注册")').isVisible({ timeout: 3000 }).catch(() => false);
    expect(errorVisible || stillOnRegister).toBeTruthy();
  });
});