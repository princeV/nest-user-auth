import { Model } from 'mongoose';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './interfaces/user.interface';
import { CreateUserDto } from './dto/create-user.dto';
import { AuthService } from '../auth/auth.service';
import { UserCredentialException } from "./exceptions/user-credential.exception.ts";


@Injectable()
export class UserService {

  constructor(@InjectModel('User')
                private readonly userModel: Model<User>,
                private readonly authService: AuthService
              ) {}

    async create(createUserDto: CreateUserDto): Promise<User> {
      const createUser = new this.userModel(createUserDto);
      return await createUser.save();
    }

    async logon(logonUserDto: any): Promise<any> {
      const user = await this.userModel.findOne({username: logonUserDto.username}).exec();

      if(user && await user.isValidPassword(logonUserDto.password)){
        return this.authService.createToken(user);
      }
      throw new UserCredentialException()
    }

    async findAll(): Promise<User[]> {
      return await this.userModel.find().exec();
    }

    async findByUsername(username: string): Promise<User[]> {
      return await this.userModel.findOne({ username: username }).exec();
    }
}
