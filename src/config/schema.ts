import { z } from 'zod';

export const SecretRefSchema = z.union([
  z.string(),
  z.object({ fromEnv: z.string().min(1) }).strict(),
  z.object({ fromFile: z.string().min(1) }).strict(),
]);

export const CouchDbConfigSchema = z
  .object({
    url: z
      .string()
      .url()
      .refine(
        (u) => {
          try {
            const parsed = new URL(u);
            return !parsed.username && !parsed.password;
          } catch {
            return false;
          }
        },
        {
          message:
            'CouchDB URL must not contain embedded username or password. Supply credentials via remote.username and remote.password.',
        }
      ),
    database: z.string().min(1).regex(/^[a-z][a-z0-9_$()+/-]*$/, {
      message: 'Invalid CouchDB database name format',
    }),
    username: z.string().optional(),
    password: SecretRefSchema.optional(),
  })
  .strict();

export const VaultConfigSchema = z
  .object({
    path: z.string().min(1),
    dedicated: z.boolean().default(false),
  })
  .strict();

export const StateConfigSchema = z
  .object({
    path: z.string().min(1).optional(),
  })
  .strict();

export const EncryptionConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    passphrase: SecretRefSchema.optional(),
  })
  .strict();

export const CliConfigSchema = z
  .object({
    write: z.union([z.boolean(), z.literal('auto-arm')]).default(false),
    autoArm: z.boolean().default(false),
    periodicScanSec: z.number().int().positive().optional(),
    concurrency: z.number().int().positive().optional(),
    debounceMs: z.number().int().positive().optional(),
    incrementalPull: z.boolean().default(true),
  })
  .strict();

export const LiveSyncConfigSchema = z
  .object({
    remote: CouchDbConfigSchema,
    vault: VaultConfigSchema,
    state: StateConfigSchema.default({}),
    encryption: EncryptionConfigSchema.optional(),
    cli: CliConfigSchema.optional(),
  })
  .strict();

export type SecretRef = z.infer<typeof SecretRefSchema>;
export type CouchDbConfig = z.infer<typeof CouchDbConfigSchema>;
export type VaultConfig = z.infer<typeof VaultConfigSchema>;
export type StateConfig = z.infer<typeof StateConfigSchema>;
export type EncryptionConfig = z.infer<typeof EncryptionConfigSchema>;
export type CliConfig = z.infer<typeof CliConfigSchema>;
export type LiveSyncConfig = z.infer<typeof LiveSyncConfigSchema>;

export interface ResolvedSecrets {
  remotePassword?: string;
  encryptionPassphrase?: string;
}

export interface LoadedConfig extends LiveSyncConfig {
  readonly resolvedVaultPath: string;
  readonly resolvedStatePath: string;
  readonly resolvedSecrets: ResolvedSecrets;
}
