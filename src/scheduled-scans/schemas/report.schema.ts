import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type ReportDocument = Report & Document;

@Schema({ timestamps: true })
export class Report {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  domain: string;

  @Prop({ type: Number, required: true })
  total_vulnerabilities: number;

  @Prop([
    {
      type: { type: String, required: true },
      count: { type: Number, required: true },
      severity: { type: String, required: true },
      top_endpoints: [{ type: String }],
    },
  ])
  vulnerabilities: {
    type: string;
    count: number;
    severity: string;
    top_endpoints: string[];
  }[];

  @Prop([{ type: String }])
  zero_vulnerabilities: string[];

  @Prop({ type: Number, required: true })
  urls_with_params: number;

  @Prop({ type: Number, required: true })
  urls_without_params: number;

  // Explicitly define createdAt and updatedAt
  @Prop({ type: Date, default: Date.now })
  createdAt: Date;

  @Prop({ type: Date, default: Date.now })
  updatedAt: Date;
}

export const ReportSchema = SchemaFactory.createForClass(Report);