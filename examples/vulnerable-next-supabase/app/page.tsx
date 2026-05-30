'use client';

import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);

export default function Page({
  searchParams
}: {
  searchParams: { message?: string };
}) {
  const message = searchParams.message ?? '<strong>Welcome</strong>';

  return (
    <main>
      <h1>Vulnerable Rock House Demo</h1>
      <div dangerouslySetInnerHTML={{ __html: message }} />
      <button
        onClick={async () => {
          await supabase.from('admin_notes').select('*');
        }}
      >
        Load admin notes
      </button>
    </main>
  );
}
