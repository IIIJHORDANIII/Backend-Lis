# Backend Lis - API para Gerenciamento de Produtos

## 🚀 Configuração Rápida

### 1. Instalar Dependências
```bash
npm install
```

### 2. Configurar Variáveis de Ambiente
Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
# AWS S3 Configuration
AWS_ACCESS_KEY_ID=sua_access_key_aqui
AWS_SECRET_ACCESS_KEY=sua_secret_key_aqui
AWS_REGION=sua_regiao_aqui
AWS_BUCKET_NAME=seu_bucket_name_aqui

# MongoDB
MONGODB_URI=sua_uri_mongodb_aqui

# JWT
JWT_SECRET=seu_jwt_secret_aqui
```

### 3. Verificar Configuração
```bash
npm run check-env
```

### 4. Iniciar Servidor
```bash
# Desenvolvimento
npm run dev

# Produção
npm start
```

## 📋 Endpoints Principais

### Autenticação
- `POST /api/register` - Registrar usuário
- `POST /api/login` - Login de usuário

### Produtos (Requer Autenticação)
- `POST /api/products` - Criar produto com imagem
- `GET /api/products` - Listar produtos
- `PUT /api/products/:id` - Atualizar produto
- `PUT /api/products/:id/with-image` - Atualizar produto com imagem
- `DELETE /api/products/:id` - Deletar produto (apenas admin)

### Admin (Requer Autenticação de Admin)
- `GET /api/admin/test-s3` - Testar configuração S3
- `POST /api/admin/cleanup-s3` - Limpar imagens órfãs do S3

## 🔧 Scripts Disponíveis

- `npm run dev` - Iniciar servidor em modo desenvolvimento
- `npm start` - Iniciar servidor em modo produção
- `npm run check-env` - Verificar configuração das variáveis de ambiente
- `npm run cleanup-s3` - Limpar imagens órfãs do S3

## 📁 Estrutura do Projeto

```
src/
├── config/
│   └── config.js          # Configurações da aplicação
├── middleware/
│   └── auth.js            # Middleware de autenticação
├── models/
│   ├── Product.js         # Modelo de produto
│   ├── User.js            # Modelo de usuário
│   ├── CustomList.js      # Modelo de lista customizada
│   └── Sale.js            # Modelo de venda
├── scripts/
│   ├── checkEnv.js        # Verificação de variáveis de ambiente
│   └── cleanupS3.js       # Limpeza de imagens órfãs
├── services/
│   └── s3Service.js       # Serviço de upload para S3
└── server.js              # Arquivo principal do servidor
```

## 🛠️ Solução de Problemas

### Problemas Comuns com Upload S3

1. **Erro: "AWS_ACCESS_KEY_ID is not configured"**
   - Execute `npm run check-env` para verificar as variáveis
   - Verifique se o arquivo `.env` existe e está configurado

2. **Erro: "Access denied to S3 bucket"**
   - Verifique se as credenciais AWS estão corretas
   - Confirme se o usuário IAM tem as permissões necessárias

3. **Erro: "File size exceeds 15MB limit"**
   - Reduza o tamanho da imagem antes do upload
   - Use compressão de imagem se necessário

4. **Erro: "Only image files are allowed"**
   - Certifique-se de que está enviando um arquivo de imagem válido
   - Verifique a extensão e o tipo MIME do arquivo

### Testando a Configuração

1. **Teste as variáveis de ambiente:**
   ```bash
   npm run check-env
   ```

2. **Teste a configuração do S3 (apenas admin):**
   ```bash
   GET /api/admin/test-s3
   Authorization: Bearer seu_token_aqui
   ```

3. **Teste o upload de imagem:**
   ```bash
   POST /api/products
   Content-Type: multipart/form-data
   Authorization: Bearer seu_token_aqui
   
   Form data:
   - name: "Produto Teste"
   - description: "Descrição do produto"
   - price: "99.99"
   - commission: "10"
   - quantity: "10"
   - category: "masculino"
   - image: [arquivo de imagem]
   ```

## 📚 Documentação Adicional

- [Configuração Detalhada do S3](S3_SETUP.md)
- [Guia de Configuração do AWS IAM](S3_SETUP.md#configuração-do-iam)
- [Solução de Problemas](S3_SETUP.md#solução-de-problemas)

## 🔒 Segurança

- Todas as rotas de upload requerem autenticação
- Apenas admins podem fazer upload de produtos
- Validação de tipo e tamanho de arquivo
- CORS configurado para origens específicas
- Limite de 15MB para upload de imagens

## 🌐 CORS

O servidor está configurado para aceitar requisições das seguintes origens:
- `http://localhost:3000`
- `http://localhost:3005`
- `https://frontend-lis.vercel.app`
- `https://www.jhorello.com.br`
- `https://lismodas.com.br`
- `https://www.lismodas.com.br`
