import type { APIRoute } from 'astro';
import nodemailer from 'nodemailer';

export const prerender = false;

// Хелпер безопасного чтения переменных из import.meta.env или process.env
function getEnv(key: string, defaultValue = ''): string {
  const metaVal = (import.meta.env as Record<string, string | undefined>)?.[
    key
  ];
  const procVal = typeof process !== 'undefined' ? process.env[key] : undefined;
  return (metaVal || procVal || defaultValue).trim();
}

function isPlaceholderValue(val: string): boolean {
  if (!val) return true;
  const v = val.toLowerCase().trim();
  return (
    v.includes('ваш_логин') ||
    v.includes('ваш_пароль') ||
    v.includes('пароль_приложения') ||
    v.includes('your_login') ||
    v.includes('your_app_password') ||
    v.includes('your_smtp_app_password') ||
    v.includes('example.com') ||
    v.includes('example.ru')
  );
}

// In-memory Rate Limiting (5 запросов за 10 минут с одного IP)
const ipRequests = new Map<string, number[]>();
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 5;

setInterval(
  () => {
    const now = Date.now();
    for (const [ip, timestamps] of ipRequests.entries()) {
      const valid = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
      if (valid.length === 0) {
        ipRequests.delete(ip);
      } else {
        ipRequests.set(ip, valid);
      }
    }
  },
  15 * 60 * 1000,
);

// Чёрный список временных почт
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'mailinator.com',
  'tempmail.com',
  '10minutemail.com',
  'guerrillamail.com',
  'sharklasers.com',
  'trashmail.com',
  'yopmail.com',
  'fakeinbox.com',
  'getairmail.com',
  'dispostable.com',
  'temp-mail.org',
  'generator.email',
  'burnermail.io',
  'dropmail.me',
  'mohmal.com',
  'crazymailing.com',
  'mytemp.email',
]);

// Спам стоп-слова
const SPAM_KEYWORDS = [
  'casino',
  'viagra',
  'cialis',
  'cryptocurrency',
  'bitcoin',
  'dating site',
  'seo ranking',
  'guest post',
  'порно',
  'прогон сайта',
  'взлом',
  'накрутка',
];

function sanitize(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export const POST: APIRoute = async ({ request, clientAddress }) => {
  try {
    const ip = clientAddress || 'unknown';
    const now = Date.now();

    // 1. Проверка Rate Limit
    const timestamps = ipRequests.get(ip) || [];
    const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

    if (recent.length >= RATE_LIMIT_MAX_REQUESTS) {
      return new Response(
        JSON.stringify({
          ok: false,
          success: false,
          error:
            'Слишком много запросов. Пожалуйста, подождите несколько минут перед повторной отправкой.',
        }),
        { status: 429, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // 2. Парсинг данных (поддержка JSON и FormData)
    let name = '';
    let tel = '';
    let email = '';
    let message = '';
    let honeypot = '';
    let formRenderTime = 0;

    const contentType = request.headers.get('content-type') || '';

    if (contentType.includes('application/json')) {
      const body = await request.json();
      name = body.name || '';
      tel = body.tel || body.phone || '';
      email = body.email || '';
      message = body.message || body.comment || '';
      honeypot =
        body.website || body.hp_check || body.honeypot || body.company || '';
      formRenderTime = Number(body._t || 0);
    } else {
      const formData = await request.formData();
      name = (formData.get('name') as string) || '';
      tel =
        (formData.get('tel') as string) ||
        (formData.get('phone') as string) ||
        '';
      email = (formData.get('email') as string) || '';
      message =
        (formData.get('message') as string) ||
        (formData.get('comment') as string) ||
        '';
      honeypot =
        (formData.get('website') as string) ||
        (formData.get('hp_check') as string) ||
        (formData.get('honeypot') as string) ||
        '';
      formRenderTime = Number(formData.get('_t') || 0);
    }

    // 3. Антиспам: Honeypot-ловушка
    if (honeypot && honeypot.trim().length > 0) {
      console.warn(`[Anti-Spam] Honeypot triggered from IP ${ip}.`);
      return new Response(
        JSON.stringify({ ok: true, success: true, message: 'Заявка принята' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // 4. Антиспам: проверка времени заполнения (не быстрее 1.5 сек)
    if (formRenderTime > 0) {
      const elapsed = now - formRenderTime;
      if (elapsed < 1500) {
        console.warn(
          `[Anti-Spam] Submission too fast (${elapsed}ms) from IP ${ip}.`,
        );
        return new Response(
          JSON.stringify({
            ok: false,
            success: false,
            error:
              'Обнаружена автоматическая отправка формы. Пожалуйста, заполните форму повторно.',
          }),
          { status: 400, headers: { 'Content-Type': 'application/json' } },
        );
      }
    }

    // 5. Валидация полей
    name = name.trim();
    tel = tel.trim();
    email = email.trim();
    message = message.trim();

    if (!name || name.length < 2) {
      return new Response(
        JSON.stringify({
          ok: false,
          success: false,
          error: 'Пожалуйста, укажите ваше имя (минимум 2 символа).',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const phoneDigits = tel.replace(/\D/g, '');
    if (!tel || phoneDigits.length < 10) {
      return new Response(
        JSON.stringify({
          ok: false,
          success: false,
          error:
            'Пожалуйста, укажите корректный номер телефона (не менее 10 цифр).',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      return new Response(
        JSON.stringify({
          ok: false,
          success: false,
          error: 'Пожалуйста, укажите корректный адрес электронной почты.',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const emailDomain = email.split('@')[1]?.toLowerCase();
    if (emailDomain && DISPOSABLE_EMAIL_DOMAINS.has(emailDomain)) {
      console.warn(
        `[Anti-Spam] Disposable email rejected: ${email} from IP ${ip}`,
      );
      return new Response(
        JSON.stringify({
          ok: false,
          success: false,
          error:
            'Использование временных e-mail адресов запрещено. Пожалуйста, укажите постоянный e-mail.',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const lowerMessage = message.toLowerCase();
    for (const keyword of SPAM_KEYWORDS) {
      if (lowerMessage.includes(keyword)) {
        console.warn(`[Anti-Spam] Keyword "${keyword}" blocked from IP ${ip}.`);
        return new Response(
          JSON.stringify({
            ok: true,
            success: true,
            message: 'Заявка принята',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
    }

    const linkMatches = message.match(/https?:\/\//gi) || [];
    if (linkMatches.length > 2) {
      console.warn(`[Anti-Spam] Link spam detected from IP ${ip}.`);
      return new Response(
        JSON.stringify({ ok: true, success: true, message: 'Заявка принята' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    recent.push(now);
    ipRequests.set(ip, recent);

    // 6. Конфигурация SMTP (поддерживает и SMTP_TO, и MAIL_TO)
    const recipient = getEnv('SMTP_TO', getEnv('MAIL_TO', 'nice-dev@list.ru'));
    const smtpHost = getEnv('SMTP_HOST', 'smtp.timeweb.ru');
    const smtpPort = Number(getEnv('SMTP_PORT', '465'));
    const smtpSecure = getEnv('SMTP_SECURE', 'true') !== 'false';
    const smtpUser = getEnv('SMTP_USER', 'info@nice-dev.ru');
    const smtpPass = getEnv('SMTP_PASS', '');

    let smtpFrom = getEnv('SMTP_FROM', getEnv('MAIL_FROM', ''));
    if (
      !smtpFrom ||
      smtpFrom.includes('your_login') ||
      smtpFrom.includes('ваш_логин')
    ) {
      smtpFrom = smtpUser
        ? `"Горящие туры и круизы" <${smtpUser}>`
        : '"Горящие туры и круизы" <info@nice-dev.ru>';
    }

    const safeName = sanitize(name);
    const safeTel = sanitize(tel);
    const safeEmail = sanitize(email);
    const safeMessage = sanitize(
      message || 'Не указаны (подбор общего характера)',
    );

    const emailSubject = `🌴 Новая заявка от ${safeName}`;

    // HTML шаблон письма без темы и даты
    const emailHtml = `
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>${emailSubject}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #1e293b; }
    .card { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.08); border: 1px solid #e2e8f0; }
    .header { background: linear-gradient(135deg, #0c2626 0%, #164e63 100%); padding: 30px 24px; color: #ffffff; text-align: center; }
    .header h1 { margin: 0; font-size: 22px; font-weight: 700; color: #deb65a; letter-spacing: 0.5px; text-transform: uppercase; }
    .header p { margin: 8px 0 0; font-size: 13px; color: #ffffff; opacity: 0.9; }
    .content { padding: 30px 24px; }
    .table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .table tr td { padding: 12px 14px; border-bottom: 1px solid #e2e8f0; font-size: 14px; vertical-align: top; }
    .table tr td:first-child { width: 140px; font-weight: 600; color: #64748b; background: #f8fafc; }
    .table tr td:last-child { color: #0f172a; }
    .message-box { background: #f8fafc; border-left: 4px solid #deb65a; padding: 14px 18px; margin-top: 5px; border-radius: 4px; font-size: 14px; line-height: 1.6; white-space: pre-wrap; color: #0f172a; }
    .footer { background: #f8fafc; padding: 16px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>🌴 Новая заявка</h1>
    </div>
    <div class="content">
      <table class="table">
        <tr>
          <td>Имя:</td>
          <td><strong>${safeName}</strong></td>
        </tr>
        <tr>
          <td>Телефон:</td>
          <td><a href="tel:${safeTel}" style="color: #0c2626; font-weight: bold; text-decoration: none;">${safeTel}</a></td>
        </tr>
        <tr>
          <td>E-mail:</td>
          <td><a href="mailto:${safeEmail}" style="color: #0284c7; font-weight: 600; text-decoration: none;">${safeEmail}</a></td>
        </tr>
        <tr>
          <td>Сообщение:</td>
          <td><div class="message-box">${safeMessage}</div></td>
        </tr>
        <tr>
          <td>IP-клиента:</td>
          <td><code>${ip}</code></td>
        </tr>
      </table>
    </div>
    <div class="footer">
      Письмо сформировано автоматически формой заявки на сайте</strong>.
    </div>
  </div>
</body>
</html>
    `;

    // Текстовая версия письма (для почтовых клиентов без HTML)
    const emailText = `
Новая заявка:
------------------------------------------
Имя: ${name}
Телефон: ${tel}
E-mail: ${email}
Пожелания: ${message || 'Не указаны'}
IP: ${ip}
------------------------------------------
Получатель: ${recipient}
    `;

    const hasCredentials = smtpUser.length > 0 && smtpPass.length > 0;
    const isPlaceholder =
      isPlaceholderValue(smtpUser) || isPlaceholderValue(smtpPass);

    if (!hasCredentials || isPlaceholder) {
      console.warn(
        `[SMTP Warning] Real SMTP credentials are not configured in .env.`,
      );
      return new Response(
        JSON.stringify({
          ok: false,
          success: false,
          error:
            'Заявка не отправлена на почту: в файле .env не заполнен или пуст параметр SMTP_PASS. Укажите реальный пароль от ящика и перезапустите dev-сервер.',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // 7. Отправка письма через Nodemailer
    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });

    await transporter.sendMail({
      from: smtpFrom,
      to: recipient,
      replyTo: email,
      subject: emailSubject,
      text: emailText,
      html: emailHtml,
    });

    console.log(`[SMTP] Successfully dispatched lead email to ${recipient}`);

    return new Response(
      JSON.stringify({
        ok: true,
        success: true,
        message: 'Спасибо! Ваша заявка успешно отправлена.',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  } catch (err: any) {
    console.error('[API Error /api/lead]:', err);

    const rawError = String(err?.message || err || '');
    let friendlyError =
      'Произошла ошибка при отправке заявки на почту. Пожалуйста, попробуйте позже или свяжитесь с нами по телефону.';

    if (
      rawError.includes('Invalid login') ||
      rawError.includes('authentication failed') ||
      rawError.includes('535')
    ) {
      friendlyError =
        'Ошибка авторизации SMTP (код 535): неверный логин или пароль. Проверьте правильность SMTP_USER и пароля SMTP_PASS в файле .env.';
    } else if (
      rawError.includes('Sender address not accepted') ||
      rawError.includes('550') ||
      rawError.includes('not authorized')
    ) {
      friendlyError =
        'Ошибка почтового сервера (код 550): адрес отправителя в SMTP_FROM должен совпадать с ящиком авторизации SMTP_USER.';
    } else if (
      rawError.includes('ECONNREFUSED') ||
      rawError.includes('ETIMEDOUT') ||
      rawError.includes('ENOTFOUND')
    ) {
      friendlyError =
        'Не удалось подключиться к почтовому серверу SMTP. Проверьте правильность SMTP_HOST и SMTP_PORT в файле .env.';
    }

    return new Response(
      JSON.stringify({
        ok: false,
        success: false,
        error: friendlyError,
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } },
    );
  }
};
