import { customAlphabet } from 'nanoid';
const nanoid = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', 8);
export const makeOrderNumber = () => `CC-${new Date().getFullYear()}-${nanoid()}`;
