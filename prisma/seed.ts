import { PrismaClient } from '@prisma/client';
import fs from 'node:fs';
import path from 'node:path';

const prisma = new PrismaClient();

type SeedProduct = {
  name: string;
  slug: string;
  description: string;
  image: string;
  category: string;
  price: number;
  stock: number;
  sizes: string[];
  colors: string[];
  featured: boolean;
  isActive: boolean;
};

async function main() {
  const productsPath = path.join(process.cwd(), 'prisma', 'products.json');
  const products = JSON.parse(fs.readFileSync(productsPath, 'utf8')) as SeedProduct[];

  for (const product of products) {
    await prisma.product.upsert({
      where: { slug: product.slug },
      update: {
        name: product.name,
        description: product.description,
        image: product.image,
        category: product.category,
        price: product.price,
        stock: product.stock,
        sizes: product.sizes,
        colors: product.colors,
        featured: product.featured,
        isActive: product.isActive,
      },
      create: {
        name: product.name,
        slug: product.slug,
        description: product.description,
        image: product.image,
        category: product.category,
        price: product.price,
        stock: product.stock,
        sizes: product.sizes,
        colors: product.colors,
        featured: product.featured,
        isActive: product.isActive,
      },
    });
  }

  console.log(`Seeded ${products.length} products successfully.`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
