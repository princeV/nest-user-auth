import { Module, forwardRef } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { UserSchema } from './schemas/user.schema';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule,
            MongooseModule.forFeature([{ name: 'User', schema: UserSchema }])
          ],
  controllers: [UserController],
  providers: [UserService]
})
export class UserModule {}
