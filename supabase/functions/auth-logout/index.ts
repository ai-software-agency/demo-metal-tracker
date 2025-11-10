import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.78.0';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Credentials': 'true',
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Extract session token from cookie to invalidate it server-side
    const cookieHeader = req.headers.get('cookie') || '';
    const sessionMatch = cookieHeader.match(/sb-session=([^;]+)/);
    
    if (sessionMatch) {
      try {
        const sessionData = JSON.parse(decodeURIComponent(sessionMatch[1]));
        
        // Create Supabase client with the user's access token
        const supabaseClient = createClient(
          Deno.env.get('SUPABASE_URL') ?? '',
          Deno.env.get('SUPABASE_ANON_KEY') ?? '',
          {
            global: {
              headers: {
                Authorization: `Bearer ${sessionData.access_token}`,
              },
            },
          }
        );

        // Invalidate the session server-side in Supabase Auth
        // This revokes the access and refresh tokens
        const { error } = await supabaseClient.auth.signOut();
        
        if (error) {
          console.error('Supabase signOut error:', error);
          // Continue with cookie clearing even if signOut fails
        } else {
          console.log('Session invalidated server-side');
        }
      } catch (parseError) {
        console.error('Error parsing session cookie:', parseError);
        // Continue with cookie clearing even if parsing fails
      }
    }

    // Clear the HttpOnly session cookie
    // Security: Setting Max-Age=0 immediately expires the cookie
    const clearCookieHeader = 'sb-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';

    console.log('Logout successful - session cookie cleared');

    return new Response(
      JSON.stringify({ success: true }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'Set-Cookie': clearCookieHeader,
        },
      }
    );
  } catch (error) {
    console.error('Logout error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
