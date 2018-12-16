import { HttpException, HttpStatus } from '@nestjs/common';

export class UserCredentialException extends HttpException {
  constructor() {
    super('Username or password is not correct', HttpStatus.BAD_REQUEST);
  }
}
