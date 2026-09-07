# FMODAS backend

## Requisitos

Instale Node.js LTS, que inclui `node` e `npm`:

```powershell
node --version
npm --version
```

## Configuração

1. Copie `.env.example` para `.env`.
2. Gere um segredo forte para `JWT_SECRET`.
3. Configure `ADMIN_EMAIL` e `ADMIN_PASSWORD`.
4. Configure as chaves do Stripe para pagamentos reais.
5. Configure SMTP para recuperação de senha por e-mail.

## Execução

```powershell
npm install
npm start
```

Abra `http://localhost:3000/cliente.html`.

## API implementada

- `POST /api/auth/register`: cadastro de cliente.
- `POST /api/auth/login`: login de cliente ou administrador.
- `POST /api/auth/logout`: encerra sessão httpOnly.
- `GET /api/auth/me`: usuário autenticado.
- `POST /api/auth/forgot-password`: envia recuperação via SMTP.
- `GET /api/products`: catálogo publicado.
- `POST/PATCH/DELETE /api/products`: gestão administrativa com upload de até 8 imagens.
- `POST /api/checkout`: cria pedido persistente e sessão Stripe quando configurado.
- `GET /api/orders`: pedidos do cliente ou todos os pedidos para admin.
- `POST /api/webhooks/stripe`: confirma pagamento pelo webhook assinado.

O banco SQLite é criado em `data/fmodas.sqlite` e os uploads em `uploads/`. Esses diretórios devem ficar fora do controle de versão em produção.
