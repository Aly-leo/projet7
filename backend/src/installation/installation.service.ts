import {
  Injectable,
  Logger,
  NotFoundException,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import { PasswordService } from '../auth/password.service.js';
import type { AuditContext } from '../common/types.js';
import { PrismaService } from '../prisma/prisma.service.js';

/** Constante fixe du verrou consultatif PostgreSQL : jamais dérivée d'une entrée utilisateur. */
const INSTALL_LOCK_ID = 7_070_001;

@Injectable()
export class InstallationService implements OnApplicationBootstrap {
  private readonly logger = new Logger(InstallationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly passwords: PasswordService,
    private readonly audit: AuditService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if ((await this.prisma.user.count()) > 0) return;
    this.logger.warn("Installation requise : ouvrez l'application pour créer le compte administrateur.");
  }

  async state(): Promise<{ installationRequise: boolean }> {
    return { installationRequise: (await this.prisma.user.count()) === 0 };
  }

  async install(
    input: { nom: string; courriel: string; motDePasse: string },
    ctx: AuditContext,
  ): Promise<void> {
    // Verrouillage définitif : 404 sans détail dès qu'un utilisateur existe.
    if ((await this.prisma.user.count()) > 0) {
      await this.audit.log(ctx, { action: 'SETUP_DENIED', outcome: 'DENIED', metadata: { reason: 'already_installed' } });
      throw new NotFoundException();
    }

    this.passwords.assertStrong(input.motDePasse, [input.courriel, input.nom]);
    const passwordHash = await this.passwords.hash(input.motDePasse);

    const created = await this.prisma.$transaction(async (tx) => {
      // Deux requêtes simultanées ne peuvent pas créer deux administrateurs.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${INSTALL_LOCK_ID})`;
      if ((await tx.user.count()) > 0) return null;
      return tx.user.create({
        data: {
          email: input.courriel,
          name: input.nom,
          passwordHash,
          role: 'ADMIN',
          mustChangePassword: false, // la personne a choisi elle-même son mot de passe
        },
        select: { id: true },
      });
    });

    if (!created) {
      await this.audit.log(ctx, { action: 'SETUP_DENIED', outcome: 'DENIED', metadata: { reason: 'race_lost' } });
      throw new NotFoundException();
    }
    await this.audit.log(ctx, {
      action: 'SETUP_ADMIN_CREATED',
      outcome: 'SUCCESS',
      userId: created.id,
      resourceType: 'User',
      resourceId: created.id,
    });
  }
}

