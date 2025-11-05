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
    // Security: Read session from HttpOnly cookie, not accessible to JavaScript
    const cookieHeader = req.headers.get('Cookie') || '';
    const sessionCookie = cookieHeader
      .split(';')
      .find(c => c.trim().startsWith('sb-session='));

    if (!sessionCookie) {
      return new Response(
        JSON.stringify({ authenticated: false, user: null }),
        { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const sessionData = JSON.parse(
      decodeURIComponent(sessionCookie.split('=')[1])
    );

    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
    );

    // Verify the session is still valid
    const { data: { user }, error } = await supabaseClient.auth.getUser(
      sessionData.access_token
    );

    if (error || !user) {
      // Clear invalid session cookie
      const clearCookie = 'sb-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';
      
      return new Response(
        JSON.stringify({ authenticated: false, user: null }),
        {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
            'Set-Cookie': clearCookie,
          },
        }
      );
    }

    // Check if user is admin using has_role function
    const { data: isAdmin, error: roleError } = await supabaseClient.rpc('has_role', {
      _user_id: user.id,
      _role: 'admin',
    });

    if (roleError) {
      console.error('Role check error:', roleError);
    }

    return new Response(
      JSON.stringify({
        authenticated: true,
        user: {
          id: user.id,
          email: user.email,
        },
        isAdmin: isAdmin || false,
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    console.error('Session check error:', error);
    return new Response(
      JSON.stringify({ authenticated: false, user: null }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
