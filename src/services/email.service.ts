import nodemailer from 'nodemailer';
import { env } from '../config/env';

const transport = nodemailer.createTransport({
  host: env.SMTP_HOST || 'localhost',
  port: parseInt(env.SMTP_PORT || '587', 10),
  secure: env.SMTP_PORT === '465',
  auth: {
    user: env.SMTP_USER || 'placeholder',
    pass: env.SMTP_PASS || 'placeholder',
  },
});

export class EmailService {
  // In-memory queue of sent emails for developer testing / sandbox
  private static sentEmails: Array<{ to: string; subject: string; body: string; sentAt: Date }> = [];

  static async sendSecurityAlert(to: string, subject: string, details: Record<string, any>) {
    const body = `Security Alert details:\n\n${Object.entries(details)
      .map(([key, value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`)
      .join('\n')}`;

    const emailEntry = { to, subject, body, sentAt: new Date() };
    this.sentEmails.push(emailEntry);

    if (this.sentEmails.length > 50) {
      this.sentEmails.shift();
    }

    console.log(`📧 [MOCK SMTP] Email sent to: ${to} | Subject: ${subject}`);

    try {
      if (env.SMTP_USER && env.SMTP_USER !== 'your-smtp-user') {
        await transport.sendMail({
          from: env.SMTP_USER,
          to,
          subject,
          text: body,
        });
      }
    } catch (err: any) {
      console.warn(`⚠️ SMTP send failed: ${err.message}. Email logged to sandbox.`);
    }
  }

  static getSentEmails() {
    return this.sentEmails;
  }

  static clearSentEmails() {
    this.sentEmails = [];
  }
}
