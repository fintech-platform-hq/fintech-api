import { IdentityEmailDelivery } from './identity-email-delivery';

describe('Identity email delivery', () => {
  const original = process.env;
  const service = new IdentityEmailDelivery();

  beforeEach(() => {
    process.env = {
      ...original,
      LENVER_LOCAL_EMAIL_MAILBOX: '',
      RESEND_API_KEY: 'synthetic-provider-key',
      LENVER_IDENTITY_MAIL_FROM: 'test@example.test',
    };
  });

  afterEach(() => {
    jest.restoreAllMocks();
    process.env = original;
  });

  it('sends a text email to the configured Resend endpoint with redirects blocked', async () => {
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }));
    await service.deliver('recipient@example.test', 'verify', '012345');
    expect(fetch).toHaveBeenCalledWith(
      'https://api.resend.com/emails',
      expect.objectContaining({
        method: 'POST',
        redirect: 'error',
        body: expect.stringContaining('012345') as string,
      }),
    );
  });

  it('redacts provider errors and uses no network when local configuration is invalid', async () => {
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('secret provider detail'));
    await expect(
      service.deliver('recipient@example.test', 'verify', '012345'),
    ).rejects.toMatchObject({
      status: 503,
      message: 'Email delivery unavailable',
    });
    process.env.LENVER_LOCAL_EMAIL_MAILBOX = 'relative-path';
    await expect(
      service.deliver('recipient@example.test', 'verify', '012345'),
    ).rejects.toMatchObject({ status: 503 });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
