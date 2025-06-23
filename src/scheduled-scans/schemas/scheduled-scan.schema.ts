import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class ScheduledScan {
  @Prop({ required: true })
  url: string;

  @Prop({ required: true, enum: ['daily', 'weekly'] })
  frequency: 'daily' | 'weekly';

  @Prop({ required: true })
  time: string; // e.g., "14:30"

  @Prop({ required: true })
  userId: string;

  @Prop({ default: Date.now })
  createdAt: Date;
}

export type ScheduledScanDocument = ScheduledScan & Document;
export const ScheduledScanSchema = SchemaFactory.createForClass(ScheduledScan);