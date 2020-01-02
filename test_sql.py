import unittest
import parsimonious
import sql

class Grammar(unittest.TestCase):
    def test_grammar(self):
        tables_desc = { 'flowrecords':{
                'tstart': 'plain',
                'tend': 'plain',
                'src_ip': 'pseudonymized',
                'dst_ip': 'pseudonymized',
                'protocol': 'plain',
                'src_port': 'plain',
                'dst_port': 'plain',
                'flows': 'plain',
                'packets': 'plain',
                'bytes': 'plain'
        } }
        args_desc = { 'tstart': 'plain',
                'tend': 'plain',
                'ip': 'pseudonymized',
                'protocol': 'plain',
                'port': 'plain'}

        check = lambda q: sql.check_query(tables_desc, args_desc, q)

        check("""SELECT flowrecords.src_ip, flowrecords.src_port,
            flowrecords.dst_ip, flowrecords.dst_port
        FROM flowrecords
        WHERE flowrecords.tstart > :tstart AND flowrecords.tend < :tend
        AND (flowrecords.src_ip = :ip OR flowrecords.dst_ip = :ip)""")

        check("""SELECT flowrecords.src_ip, flowrecords.src_port,
        flowrecords.dst_ip, flowrecords.dst_port
        FROM flowrecords
        WHERE flowrecords.tstart > :tstart AND flowrecords.tend < :tend
                        AND
            (flowrecords.src_ip = :ip OR flowrecords.dst_ip = :ip)
                        AND
            flowrecords.protocol = :protocol
                        AND
            (flowrecords.src_port = :port 
                OR flowrecords.dst_port = :port)""")

        check("""SELECT flowrecords.dst_ip, 
            flowrecords.protocol, 
            flowrecords.dst_port, 
            SUM(flowrecords.flows), 
            SUM(flowrecords.packets), 
            SUM(flowrecords.bytes) 
        FROM flowrecords
        WHERE flowrecords.tstart > :tstart AND flowrecords.tend < :tend
            AND
            flowrecords.src_ip = :ip 
        GROUP BY flowrecords.dst_ip, 
            flowrecords.protocol, flowrecords.dst_port""")

        check("""SELECT flowrecords.protocol, 
            flowrecords.dst_port, 
            SUM(flowrecords.flows), 
            SUM(flowrecords.packets), 
            SUM(flowrecords.bytes) 
        FROM flowrecords""")
        
        # we don't allow SELECT *
        with self.assertRaises(sql.InvalidQuery):
            check("SELECT *")

        # we don't allow naked column names
        with self.assertRaises(sql.InvalidQuery):
            check("SELECT src_port FROM flowrecords")

        # we don't allow undescribed columns
        with self.assertRaises(sql.InvalidQuery):
            check("SELECT flowrecords.extra_column FROM flowrecords ")

        # we don't allow non-trivial operations on pseudonymized data
        # (except for counting)
        with self.assertRaises(sql.InvalidQuery):
            check("""SELECT "source ip is "+flowrecords.src_ip
                    FROM flowrecords""")

        # we don't allow > of pseudonymized data
        with self.assertRaises(sql.InvalidQuery):
            check("""SELECT flowrecords.src_ip
                    FROM flowrecords
                    WHERE flowrecords.src_ip > flowrecords.dst_ip""")

        # we don't allow comparisons of pseudonymized and plain data
        with self.assertRaises(sql.InvalidQuery):
            check("""SELECT flowrecords.src_ip
                    FROM flowrecords
                    WHERE flowrecords.src_ip = flowrecords.src_port""")

        # we don't allow ordering by pseudonymized data
        with self.assertRaises(sql.InvalidQuery):
            check("""SELECT flowrecords.src_ip
                    FROM flowrecords
                    ORDER BY flowrecords.src_ip""")


if __name__ == '__main__':
    unittest.main()
