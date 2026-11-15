import { unlinkSync, existsSync, rmSync } from 'fs';

/**
 * 全局设置 - 在所有测试前清理状态
 * 
 * 注意：Playwright 执行顺序是 webServer 启动 → globalSetup → 测试
 * 所以这里不能清空数据库目录，否则会删除服务器刚创建的表
 * 
 * 解决方案：
 * 1. 只清理状态文件（让测试重新创建管理员）
 * 2. 让服务器自己管理数据库生命周期
 */
async function globalSetup() {
  const stateFile = '/tmp/goauth-e2e-admin-state.json';
  // 数据库目录基于项目根目录（global-setup 位于 tests/e2e/ 下）
  const dbPath = `${__dirname}/../../data`;
  
  console.log('🔧 全局设置: 清理测试状态...');
  
  try {
    // 清理所有状态文件
    const stateFiles = [
      stateFile,
      '/tmp/goauth-e2e-invitation-edge.json',
      '/tmp/goauth-e2e-admin-protection.json',
    ];
    
    for (const file of stateFiles) {
      if (existsSync(file)) {
        unlinkSync(file);
        console.log(`✅ 已清理状态文件: ${file}`);
      }
    }
    
    // 清理临时状态文件（旧版本可能使用不同路径）
    const oldStateFile = `${__dirname}/.admin-state.json`;
    if (existsSync(oldStateFile)) {
      unlinkSync(oldStateFile);
    }
    
    console.log('✅ 全局设置完成');
  } catch (error) {
    console.error('❌ 全局设置失败:', error);
  }
}

export default globalSetup;
