/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Controller, Post, Body } from '@nestjs/common';
import { ChatService } from './chat.service';

@Controller('chat')
export class ChatController {
  constructor(private readonly chatService: ChatService) {}

  @Post()
  async getReply(@Body('message') message: string, @Body('choice') choice?: number) {
    const response = await this.chatService.getBotResponse(message);
    if (response.status === 'choice_required' && choice !== undefined) {
      // إذا تم اختيار خيار، أعد تشغيل الدالة مع السؤال المحدد
      const newMessage = response.choices[choice.toString()];
      return this.chatService.getBotResponse(newMessage);
    }
    return response;
  }
}