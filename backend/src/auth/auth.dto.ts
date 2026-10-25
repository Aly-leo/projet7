import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';

const normalizeEmail = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim().toLowerCase() : value;

export class LoginDto {
  @Transform(normalizeEmail) @IsEmail() @MaxLength(254) courriel!: string;
  @IsString() @MinLength(1) @MaxLength(128) motDePasse!: string;
}

export class ChangePasswordDto {
  @IsString() @MinLength(1) @MaxLength(128) motDePasseActuel!: string;
  @IsString() @MaxLength(128) nouveauMotDePasse!: string;
}

export { normalizeEmail };
