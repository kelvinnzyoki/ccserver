import { PrismaClient, Prisma } from '@prisma/client';
import productsData from './products.json' assert { type: 'json' };

const prisma = new PrismaClient();

type ProductSeed = {
  name: string;
  slug: string;
  description: string;
  price: number;
  compareAtPrice?: number | null;
  image: string;
  images: string[];
  category: string;
  badge?: string | null;
  sku: string;
  stock: number;
  isActive: boolean;
  isFeatured: boolean;
  tags: string[];
};

const money = (value: number) => new Prisma.Decimal(value);

async function main() {
  const products = productsData as ProductSeed[];

  for (const product of products) {
    await prisma.product.upsert({
      where: { slug: product.slug },
      update: {
        name: product.name,
        description: product.description,
        price: money(product.price),
        compareAtPrice:
          product.compareAtPrice == null ? null : money(product.compareAtPrice),
        image: product.image,
        images: product.images,
        category: product.category,
        badge: product.badge ?? null,
        sku: product.sku,
        stock: product.stock,
        isActive: product.isActive,
        isFeatured: product.isFeatured,
        tags: product.tags,
      },
      create: {
        name: product.name,
        slug: product.slug,
        description: product.description,
        price: money(product.price),
        compareAtPrice:
          product.compareAtPrice == null ? null : money(product.compareAtPrice),
        image: product.image,
        images: product.images,
        category: product.category,
        badge: product.badge ?? null,
        sku: product.sku,
        stock: product.stock,
        isActive: product.isActive,
        isFeatured: product.isFeatured,
        tags: product.tags,
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
