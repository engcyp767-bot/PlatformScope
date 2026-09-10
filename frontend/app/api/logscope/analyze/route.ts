import { NextResponse } from 'next/server';

export const runtime = 'nodejs';

const gatewayUrl = (process.env.GATEWAY_INTERNAL_URL || 'http://127.0.0.1:8081').replace(/\/+$/, '');
const FORWARDED_HEADERS = ['content-type', 'cookie', 'x-filename', 'x-source-system', 'cache-control'];

/** Streams the upload to the private Gateway without a 10 MB proxy buffer. */
export async function POST(request: Request): Promise<Response> {
  const headers = new Headers();
  for (const name of FORWARDED_HEADERS) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }

  try {
    const upstream = await fetch(`${gatewayUrl}/api/logscope/analyze`, {
      method: 'POST',
      headers,
      body: request.body,
      // Required by Node's fetch when the request body is streamed.
      duplex: 'half',
    } as RequestInit & { duplex: 'half' });
    const responseHeaders = new Headers();
    for (const name of ['content-type', 'cache-control', 'x-request-id']) {
      const value = upstream.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return NextResponse.json(
      { error: 'محرك التحليل غير متاح حاليًا. لم يبدأ رفع الملف؛ تحقق من تشغيل المنصة ثم أعد المحاولة.', code: 'gateway_unavailable' },
      { status: 503 },
    );
  }
}
