require('dotenv').config();

console.log('🔍 Verificando configuração das variáveis de ambiente...\n');

const requiredEnvVars = [
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY', 
  'AWS_REGION',
  'AWS_BUCKET_NAME',
  'MONGODB_URI',
  'JWT_SECRET'
];

let allConfigured = true;

requiredEnvVars.forEach(envVar => {
  const value = process.env[envVar];
  if (value) {
    console.log(`✅ ${envVar}: Configurado`);
  } else {
    console.log(`❌ ${envVar}: NÃO CONFIGURADO`);
    allConfigured = false;
  }
});

console.log('\n' + '='.repeat(50));

if (allConfigured) {
  console.log('🎉 Todas as variáveis de ambiente estão configuradas!');
  console.log('✅ O servidor deve funcionar corretamente.');
} else {
  console.log('⚠️  Algumas variáveis de ambiente não estão configuradas.');
  console.log('📝 Verifique o arquivo .env e siga as instruções em S3_SETUP.md');
}

console.log('\n📋 Resumo da configuração:');
console.log(`🌍 Região AWS: ${process.env.AWS_REGION || 'NÃO CONFIGURADO'}`);
console.log(`🪣 Bucket S3: ${process.env.AWS_BUCKET_NAME || 'NÃO CONFIGURADO'}`);
console.log(`🔗 MongoDB: ${process.env.MONGODB_URI ? 'Configurado' : 'NÃO CONFIGURADO'}`);
console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Configurado' : 'NÃO CONFIGURADO'}`); 