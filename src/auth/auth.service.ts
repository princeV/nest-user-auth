import * as jwt from 'jsonwebtoken';
import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  constructor() {}

  async createToken(payload: any): Promise<any> {

    const expiresIn = 3600 ;
    const secretOrKey = 'secretKey';
    const user = {
      "id":payload.id,
      "username": payload.username,
      "roles": payload.roles
    };

    return jwt.sign(user, secretOrKey, {expiresIn});
  }
}
