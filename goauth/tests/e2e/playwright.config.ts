import { defineConfig, devices } from '@playwright/test';

/**
 * Goauth E2E Test Configuration
 * 
 * 完整的前端 E2E 测试配置，覆盖：
 * - 首次启动流程
 * - 用户注册/登录
 * - 管理后台功能
 * - OIDC 授权流程
 * - 用户设置
 * - 密码重置
 */
export default defineConfig({
  testDir: '.',
  
  // 测试文件匹配模式
  testMatch: '**/*.spec.ts',
  
  // 完全并行运行测试（单个文件内）
  fullyParallel: false,
  
  // 测试超时时间
  timeout: 30000,
  
  // CI 环境下禁止 test.only
  forbidOnly: !!process.env.CI,
  
  // CI 环境下重试次数
  retries: process.env.CI ? 2 : 0,
  
  // 单线程运行避免数据库状态冲突
  workers: 1,
  
  // 全局设置 - 清理数据库
  globalSetup: require.resolve('./global-setup'),
  
  // 报告器配置
  reporter: [
    ['html', { outputFolder: 'html-report' }],
    ['json', { outputFile: 'results.json' }],
    ['list']
  ],
  
  // 全局测试设置
  use: {
    // 基础 URL - goauth 默认端口 3000
    baseURL: process.env.GOAUTH_BASE_URL || 'http://localhost:3000',
    
    // 失败时收集 trace
    trace: 'on-first-retry',
    
    // 失败时截图
    screenshot: 'only-on-failure',
    
    // 重试时录制视频
    video: 'on-first-retry',
    
    // 导航超时
    navigationTimeout: 15000,
    
    // 操作超时
    actionTimeout: 10000,
  },

  // 浏览器项目配置 - 串行执行，每个项目独立数据库
  projects: [
    // Chromium - 主要测试浏览器
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
          ],
        },
      },
    },
  ],

  // 自动启动服务器
  webServer: {
    // 在启动服务器前先清理数据库，确保干净的测试环境
    // 使用项目根目录的相对路径，保证在任何环境下都能正确清理
    // 启动后立即用 CLI 创建固定管理员 e2e_admin，供各测试文件复用
    //（否则第一个注册的用户会成为管理员，破坏"普通用户权限"等测试的前提）
    // 注意：测试环境使用 APP_SECURITY_AUTOAPPROVEUSERS=true 自动批准用户
    command: 'bash ./start-server.sh',
    port: 3000,
    timeout: 60000,
    reuseExistingServer: false,
    stdout: 'ignore',
    stderr: 'pipe',
    env: {
      APP_SECURITY_AUTOAPPROVEUSERS: 'true',
    },
  },
});