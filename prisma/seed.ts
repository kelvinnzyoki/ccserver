import { PrismaClient } from '@prisma/client';
const prisma=new PrismaClient();
const products=[
 {name:'Heritage Linen Shirt',slug:'heritage-linen-shirt',description:'Breathable premium linen shirt for elegant everyday styling.',price:3200,compareAtPrice:3900,image:'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?q=80&w=1200',category:'Apparel',badge:'New',sku:'CC-LIN-001',stock:25,isFeatured:true,tags:['linen','shirt']},
 {name:'Artisan Leather Tote',slug:'artisan-leather-tote',description:'Structured leather tote with refined finish and durable handles.',price:6800,image:'https://images.unsplash.com/photo-1590874103328-eac38a683ce7?q=80&w=1200',category:'Accessories',badge:'Featured',sku:'CC-BAG-001',stock:12,isFeatured:true,tags:['bag','leather']},
 {name:'Classic Street Sneakers',slug:'classic-street-sneakers',description:'Minimal sneakers designed for comfort and polished casual outfits.',price:5400,compareAtPrice:6200,image:'https://images.unsplash.com/photo-1542291026-7eec264c27ff?q=80&w=1200',category:'Footwear',badge:'Sale',sku:'CC-SNK-001',stock:18,isFeatured:true,tags:['sneakers']}
];
async function main(){ for(const p of products) await prisma.product.upsert({where:{sku:p.sku},update:p,create:p}); }
main().finally(()=>prisma.$disconnect());
