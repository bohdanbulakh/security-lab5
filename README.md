# Лабораторна робота 5

Розширення [лабораторної роботи 4](https://github.com/bohdanbulakh/security-lab4) (token_auth + Auth0 password grant,
створення користувача, refresh token) перевіркою сигнатури JWT.

## Перевірка підпису JWT (`jwt.js`)

- Публічний ключ тенанта завантажується з `https://<AUTH0_DOMAIN>/pem` (сертифікат X.509) при старті сервера.
  Якщо підпис не зійшовся, ключ завантажується ще раз (key rotation), але не частіше ніж раз на хвилину.
- Перевірка: 3 частини токена, `alg` тільки з дозволеного списку (`RS256`, тому `alg=none` і `HS256` не проходять),
  підпис `RSA-SHA256` (`crypto.verify`), `iss` = `https://<AUTH0_DOMAIN>/`, `aud`, `exp`, `nbf`, `iat`.
- `access_token` перевіряється з `aud` = `AUTH0_AUDIENCE`, `id_token` - з `aud` = `AUTH0_CLIENT_ID`.
- Токени від Auth0 (вхід і refresh) потрапляють у сесію лише після перевірки, дані користувача беруться
  з перевіреного `id_token`.
- Middleware `requireAuth` перевіряє підпис `access_token` перед кожним захищеним запитом (після оновлення через
  refresh token, якщо воно потрібне). Невалідний токен - сесія знищується, 401.
- `POST /api/verify` `{ "token": "...", "type": "access" | "id" }` - перевірка довільного токена.

`AUTH0_AUDIENCE` обов'язковий: без нього Auth0 видає непрозорий access token, а не JWT.

## Зашифрований payload JWT (`jwe.js`, додаткове завдання)

Замість id сесії клієнт отримує JWT із зашифрованим payload (JWE Compact Serialization, RFC 7516):

```
BASE64URL(header).BASE64URL(encrypted key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)
```

- `alg: RSA-OAEP-256` - випадковий 256-бітний ключ вмісту шифрується публічним RSA ключем сервера.
- `enc: A256GCM` - payload `{ sid, sub, email, iat, exp }` шифрується AES-256-GCM; заголовок захищений як AAD,
  тому будь-яка зміна токена дає помилку розшифрування.
- Пара ключів RSA 2048 генерується при першому запуску в `keys/` (у git не потрапляє).
- Час життя токена сесії - `SESSION_TOKEN_TTL_SECONDS` (за замовчуванням 86400 с).

Сервер розшифровує токен у кожному запиті, бере з нього `sid` і перевіряє, що `sub` збігається з користувачем сесії.

## Запуск

```bash
cp .env.example .env   # вписати domain / client_id / client_secret / audience
npm install
npm start              # http://localhost:3000
```

Налаштування Auth0 такі самі, як у лаб. 4: гранти Password, Refresh Token, Client Credentials, доступ до
Management API зі scope `create:users`.

## Postman

У `postman/` лежать колекція і environment "Security lab 5". Крім запитів лаб. 4 є перевірка справжнього
access token, токена зі зміненим `sub` (invalid_signature), токена з `alg=none` (invalid_algorithm) і запит
із пошкодженим токеном сесії (Cannot decrypt token).
