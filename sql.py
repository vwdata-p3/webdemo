import parsimonious
import importlib.resources

def check_query(db_desc, param_desc, query):
    """Checks the query is admissible, and returns a tuple containing 
    'plain' and 'pseudonymized' describing the result.  

    The argument db_desc describes the columns;
    
        db_desc['table']['column']

    should be either 'plain' or 'pseudonymized'.
    
    Similarly, param_desc[i] describes whether parameter :i is a pseudonym."""
    try: 
        return QueryChecker(db_desc, param_desc).parse(query)
    except parsimonious.exceptions.ParseError as e:
        raise InvalidQuery(f"couldn't parse sql query: {e}")
    except parsimonious.exceptions.VisitationError as e:
        raise InvalidQuery(f'invalid operation used in query: {e}')

class QueryChecker(parsimonious.NodeVisitor):
    def __init__(self, db_desc, param_desc):
        for v in param_desc.values():
            assert(v in ('plain','pseudonymized'))
        for table,column_desc in db_desc.items():
            for column, v in column_desc.items():
                assert(v in ('plain','pseudonymized'))

        self.grammar = grammar
        self.db_desc = db_desc
        self.param_desc = param_desc

    def generic_visit(self, node, children):
        result = None
        for child in children:
            if child==None:
                continue
            assert(result==None)
            result = child
        return result

    def visit_column_ref(self, node, children):
        (table_name_node, dot_node, __node, column_name_node) = node
        
        table_name = table_name_node.text.rstrip().lower()
        column_name = column_name_node.text.rstrip().lower()

        if table_name not in self.db_desc:
            raise InvalidQuery(f"Unknown table {table_name}")
    
        table_desc = self.db_desc[table_name]

        if column_name not in table_desc:
            raise InvalidQuery(f"Table '{table_name}' has no column"
                    f" '{column_name}'.")

        return table_desc[column_name]
    
    def visit_parameter(self, node, children):
        (dollar_node, number_node, __node) = node
        n = number_node.text.rstrip()
        if n not in self.param_desc:
            raise InvalidQuery(f"Undescribed parameter ':{n}'.")
        return self.param_desc[n]

    def visit_string(self, node, children):
        return "plain"

    visit_number = visit_string

    def visit_add_tail(self, node, children):
        for child in children:
            if child=="plain":
                continue
            raise InvalidQuery("invalid operation on pseudonyms")
        return "plain"

    visit_mult_tail = visit_mult_expr = visit_add_expr = visit_add_tail

    def visit_exprs(self, node, children):
        return [children[0]]+children[1]

    def visit_exprs_tail(self, node, children):
        return children

    visit_sort_specs = visit_exprs
    visit_sort_specs_tail = visit_exprs_tail

    def visit_comp_expr(self, node, children):
        left, op, _, right = children
        left_node, op_node, __node, right_node = node
        if left!=right:
            raise InvalidQuery("comparing a pseudonym with plain text")
        if left=="pseudonymized":
            opname = op_node.text.rstrip() 
            if opname in ("<","<=", ">", ">="):
                raise InvalidQuery("can't use <, <=, >, >= on pseudonyms")
            assert(opname in ("=", "<>"))
        return None

    def visit_sum(self, node, children):
        count, eow, _, expr = children
        if expr=="pseudonymized":
            raise InvalidQuery("can't SUM(-) pseudonymized data")

    def visit_count(self, node, children):
        return "plain" # yes, pseudonyms can be counted

    def visit_sort_spec(self, node, children):
        if children[0]=="pseudonymized":
            raise InvalidQuery("can't order by pseudonymized data")

    def visit_group_by_clause(self, node, children):
        pass # don't pass along children

    def visit_limit_clause(self, node, children):
        pass # don't pass along children

    

class InvalidQuery(Exception): pass

with importlib.resources.open_text('resources', "sql.grammar") as f:
    grammar = parsimonious.Grammar(f.read())

