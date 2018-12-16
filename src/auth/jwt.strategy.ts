import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'secretKey',
    });
  }

/*  Seems like the check for the jwt token is done in the background
    This function has to be implemented but will only be used for
    additional checks on the payload
*/
  async validate(payload: any, done: Function) {
    done(null, payload);
  }
}
