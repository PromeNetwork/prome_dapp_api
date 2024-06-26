import {
  Controller,
  Get,
  Request,
  Param,
  Post,
  Query,
  UseGuards,
  Body,
} from '@nestjs/common';
import { TaskService } from './task.service';
import { Task } from './task.dto';
import { BadRequestException } from '@nestjs/common';
import { HttpSuccess } from '../utils/HttpSuccess';
import { JwtAuthGuard } from '../auth/jwt.guard';

@Controller('task')
export class TaskController {
  constructor(private readonly taskService: TaskService) {}

  @Get('tasks/:address')
  async queryTasks(
    @Param() param,
    @Request()
    request: any,
  ) {
    if (!param.address) {
      throw new BadRequestException('Wallet address not found');
    }
    return new HttpSuccess(
      await this.taskService.queryTasks(param.address.toLowerCase()),
    );
  }

  @Post('twitter/add')
  @UseGuards(JwtAuthGuard)
  async addTwitterTask(@Body() task: Task) {
    return new HttpSuccess(await this.taskService.addTwitterTask(task));
  }
  @Get('coupons/:address')
  async queryCoupons(
    @Param() param,
    @Request()
    request: any,
  ) {
    if (!param.address) {
      throw new BadRequestException('Wallet address not found');
    }
    return new HttpSuccess(
      await this.taskService.queryCoupons(param.address.toLowerCase()),
    );
  }

  @Get('tweet/:id')
  async getTweetDetail(@Param('id') id: string) {
    return new HttpSuccess(await this.taskService.getTweetDetail(id));
  }

  @Get('user/me')
  async queryTwitterUser() {
    return new HttpSuccess(await this.taskService.queryUserMe());
  }
  @Get('tweet/like')
  async queryTwitterLike(
    @Query('token') token: string,
    @Query('userId') userId: string,
  ) {
    return new HttpSuccess(
      await this.taskService.queryTwitterLike(token, userId),
    );
  }
}
