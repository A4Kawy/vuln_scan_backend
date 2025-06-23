/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/prefer-promise-reject-errors */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { Injectable } from '@nestjs/common';
import { PythonShell, PythonShellError } from 'python-shell';

@Injectable()
export class ChatService {
  async getBotResponse(message: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const pyshell = new PythonShell('test.py', {
        mode: 'text', // يمكن تغييره إلى 'json' إذا كان الإصدار يدعمه
        pythonOptions: ['-u'],
        scriptPath: 'C:\\Users\\Mohamed\\OneDrive\\Desktop\\vulnscanner\\vuln\\SKF-Chatbot\\Basic_Approach',
        args: [message],
        pythonPath: 'python', // استبدل بمسار دقيق إذا لزم الأمر
        cwd: 'C:\\Users\\Mohamed\\OneDrive\\Desktop\\vulnscanner\\vuln\\SKF-Chatbot\\Basic_Approach',
      });

      let result = '';

      pyshell.on('message', (msg: string) => {
        console.log('Python Output:', msg);
        result = msg; // استبدال الإخراج بالرسالة الأخيرة فقط
      });

      pyshell.on('error', (err: PythonShellError) => {
        console.error('Python Error Details:', err.stack || err.message);
        reject(err.message || 'Error executing Python script');
      });

      pyshell.end((err: Error | null) => {
        if (err) {
          console.error('End Error Details:', err.stack || err.message);
          try {
            const response = JSON.parse(result);
            if (response.error) {
              resolve({ status: 'error', ...response });
            } else {
              reject('Error executing Python script');
            }
          } catch (e) {
            reject('Error executing Python script');
          }
        } else {
          try {
            const response = JSON.parse(result);
            if (response.type === 'choice_required') {
              resolve(response);
            } else {
              resolve({ status: 'success', ...response });
            }
          } catch (e) {
            console.error('JSON Parse Error:', e);
            resolve({ status: 'error', message: result || 'Invalid response format' });
          }
        }
      });
    });
  }
}