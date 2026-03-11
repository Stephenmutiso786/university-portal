module.exports = {
  apps: [
    {
      name: 'techhub-portal',
      script: './index.js',
      cwd: '/home/ofx_steve/university-portal/backend',
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      max_memory_restart: '400M',
      env: {
        NODE_ENV: 'production',
        PORT: 4000
      }
    }
  ]
}
