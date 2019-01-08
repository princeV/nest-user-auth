import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector, readonly authService: AuthService) { }

  async canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!roles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    //check if auth token is available
    if(!request.headers.authorization){
      throw new UnauthorizedException();
      return false;
    }
    const token = request.headers.authorization.replace('Bearer ','');
    const payload = await this.authService.decodeToken(token);

    const hasRole = () => payload.roles.some((role) => roles.includes(role));

    const validRequest = payload && payload.roles && hasRole();
    if (!validRequest) {
      throw new UnauthorizedException();
    }
    return validRequest;
  }
}
