export class CreateUserDto {
  readonly username: string;
  readonly password: string;
  readonly email: string;
  readonly roles: Array<string>;
}
