import { Test, TestingModule } from '@nestjs/testing';
import { AuthGuard, AuthenticatedRequest } from '../auth/auth.guard';
import { AccountsController } from './accounts.controller';
import { AccountsService } from './accounts.service';
import { CreateAccountDto } from './dto/create-account.dto';

describe('AccountsController', () => {
  const response = {
    id: '10000000-0000-4000-8000-000000000001',
    name: 'Main',
    currency: 'BRL',
    createdAt: '2026-09-10T15:00:00.000Z',
  };
  const userId = '10000000-0000-4000-8000-000000000010';

  let controller: AccountsController;
  let listAccounts: jest.Mock;
  let createAccount: jest.Mock;

  beforeEach(async () => {
    listAccounts = jest.fn().mockResolvedValue([response]);
    createAccount = jest.fn().mockResolvedValue(response);
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AccountsController],
      providers: [
        {
          provide: AccountsService,
          useValue: { listAccounts, createAccount },
        },
      ],
    })
      .overrideGuard(AuthGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .compile();

    controller = module.get<AccountsController>(AccountsController);
  });

  it('lists accounts for the authenticated principal', async () => {
    await expect(
      controller.listAccounts({
        principal: { userId },
      } as AuthenticatedRequest),
    ).resolves.toEqual([response]);
    expect(listAccounts).toHaveBeenCalledWith(userId);
  });

  it('creates an account for the authenticated principal', async () => {
    const dto: CreateAccountDto = { name: 'Main', currency: 'BRL' };

    await expect(
      controller.createAccount(dto, {
        principal: { userId },
      } as AuthenticatedRequest),
    ).resolves.toEqual(response);
    expect(createAccount).toHaveBeenCalledWith(dto, userId);
  });
});
