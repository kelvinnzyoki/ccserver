import axios from 'axios';
import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';
export class PaystackService {
  private headers(){ if(!env.PAYSTACK_SECRET_KEY) throw new ApiError(500,'Paystack is not configured'); return { Authorization:`Bearer ${env.PAYSTACK_SECRET_KEY}` }; }
  async initialize(orderId:string,email:string,amountKes:number){
    const amount = Math.round(amountKes * 100);
    const { data } = await axios.post('https://api.paystack.co/transaction/initialize', { email, amount, currency: env.CURRENCY, reference: orderId, callback_url: env.PAYSTACK_CALLBACK_URL, metadata:{ orderId } }, { headers: this.headers() });
    return data.data as { authorization_url:string; reference:string; access_code:string };
  }
  async verify(reference:string){ const { data } = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, { headers: this.headers() }); return data.data; }
}
export const paystack = new PaystackService();
