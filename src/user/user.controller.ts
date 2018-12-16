import { Controller, UseGuards, Get, Post, Body, Put, Param, Delete, Query, Req } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { LogonUserDto } from './dto/logon-user.dto';
import { UserService } from './user.service';
import { User } from './interfaces/user.interface';
import { AuthGuard } from '@nestjs/passport';

@Controller('api/user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    this.userService.create(createUserDto);
  }

  @Post('logon')
  async userLogon(@Body() logonUserDto: LogonUserDto): Promise<any> {
    return await this.userService.logon(logonUserDto);
  }

  @Get()
  @UseGuards(AuthGuard('jwt'))
  async findAll(@Req() request): Promise<User[]> {
    // all userdata here (no pwd)
    console.log(request.user);
    return this.userService.findAll();
  }

  @Get(':username')
  findOne(@Param('username') username) {
    return this.userService.findByUsername(username);
  }

  @Put(':id')
  update(@Param('id') id, @Body() updateCatDto) {
    return `This action updates a #${id} user`;
  }

  @Delete(':id')
  remove(@Param('id') id) {
    return `This action removes a #${id} user`;
  }

}
