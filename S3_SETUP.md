# Configuração do AWS S3 para Upload de Imagens

## Variáveis de Ambiente Necessárias

Crie um arquivo `.env` na raiz do projeto Backend-Lis com as seguintes variáveis:

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

## Configuração do Bucket S3

1. **Criar um bucket S3:**
   - Acesse o AWS Console
   - Vá para o serviço S3
   - Clique em "Create bucket"
   - Escolha um nome único para o bucket
   - Selecione a região desejada
   - Configure as permissões conforme necessário

2. **Configurar CORS no bucket:**
   ```json
   [
     {
       "AllowedHeaders": ["*"],
       "AllowedMethods": ["GET", "POST", "PUT", "DELETE"],
       "AllowedOrigins": [
         "http://localhost:3000",
         "http://localhost:3005",
         "https://frontend-lis.vercel.app",
         "https://www.jhorello.com.br",
         "https://lismodas.com.br",
         "https://www.lismodas.com.br"
       ],
       "ExposeHeaders": []
     }
   ]
   ```

3. **Configurar política de bucket (opcional):**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "PublicReadGetObject",
         "Effect": "Allow",
         "Principal": "*",
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::seu-bucket-name/*"
       }
     ]
   }
   ```

## Configuração do IAM

Crie um usuário IAM com as seguintes permissões:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::seu-bucket-name",
        "arn:aws:s3:::seu-bucket-name/*"
      ]
    }
  ]
}
```

## Testando a Configuração

1. **Inicie o servidor:**
   ```bash
   npm run dev
   ```

2. **Teste a configuração do S3 (apenas admin):**
   ```bash
   GET /api/admin/test-s3
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
   - quantity: "10"
   - category: "masculino"
   - image: [arquivo de imagem]
   ```

## Limitações e Validações

- **Tamanho máximo do arquivo:** 15MB
- **Tipos de arquivo permitidos:** Apenas imagens (image/*)
- **Autenticação:** Todas as rotas de upload requerem autenticação
- **Permissões:** Apenas admins podem fazer upload de produtos

## Solução de Problemas

### Erro: "AWS_ACCESS_KEY_ID is not configured"
- Verifique se a variável `AWS_ACCESS_KEY_ID` está definida no arquivo `.env`

### Erro: "Access denied to S3 bucket"
- Verifique se as credenciais AWS estão corretas
- Verifique se o usuário IAM tem as permissões necessárias

### Erro: "S3 bucket does not exist"
- Verifique se o nome do bucket está correto na variável `AWS_BUCKET_NAME`
- Verifique se o bucket existe na região especificada

### Erro: "File size exceeds 5MB limit"
- Reduza o tamanho da imagem antes do upload
- Use compressão de imagem se necessário

### Erro: "Only image files are allowed"
- Certifique-se de que está enviando um arquivo de imagem válido
- Verifique a extensão e o tipo MIME do arquivo 