from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
import traceback
import pathlib

try:
    import capa.main
    import capa.rules
    import capa.render.result_document as rd
    import capa.render.utils as rutils

    HAVE_CAPA = True
except ImportError:
    HAVE_CAPA = False

class FlareCapa(ProcessingModule):
    name = 'flare_capa'
    description = 'Analyze executable files using Flare Capa.'
    acts_on = ['executable']
    config = [
        {
            'name': 'rules',
            'type': 'str',
            'description': 'Path for Capa rules. The directory needs to be created manually and can be cloned from https://github.com/mandiant/capa-rules'
        }
    ]

    def initialize(self):
        if not HAVE_CAPA:
            raise ModuleInitializationError(self, 'Missing dependency: flare-capa')

    def compute_layout(self, rules, extractor, capabilities):
        """
        compute a metadata structure that links basic blocks
        to the functions in which they're found.
        only collect the basic blocks at which some rule matched.
        otherwise, we may pollute the json document with
        a large amount of un-referenced data.
        """
        functions_by_bb = {}
        bbs_by_function = {}
        for f in extractor.get_functions():
            bbs_by_function[f.address] = []
            for bb in extractor.get_basic_blocks(f):
                functions_by_bb[bb.address] = f.address
                bbs_by_function[f.address].append(bb.address)

        matched_bbs = set()
        for rule_name, matches in capabilities.items():
            rule = rules[rule_name]
            if capa.rules.Scope.BASIC_BLOCK in rule.scopes:
                for (addr, match) in matches:
                    assert addr in functions_by_bb
                    matched_bbs.add(addr)

        layout = {
            "functions": {
                f: {
                    "matched_basic_blocks": [bb for bb in bbs if bb in matched_bbs]
                    # this object is open to extension in the future,
                    # such as with the function name, etc.
                }
                for f, bbs in bbs_by_function.items()
            }
        }

        return layout


    def each(self, target):
        self.results = {}
        rules_path = pathlib.Path(self.rules)
        target_path = pathlib.Path(target)

        try:
            rules = capa.rules.get_rules([rules_path])
            extractor = capa.loader.get_extractor(target_path, "auto", "auto", capa.main.BACKEND_VIV, [], False, disable_progress=True)
            capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)
        except Exception as error:
            traceback.print_exc()
            raise ModuleExecutionError('Could not run capa on target with error: ' + str(error))

        meta = capa.loader.collect_metadata([], target_path, "auto", "auto",  [rules_path], extractor, capabilities)
        # meta['analysis'].update(capabilities.feature_counts)
        # meta["analysis"]["layout"] = self.compute_layout(rules, extractor, capabilities)
        # meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)
        meta.analysis.layout = self.compute_layout(rules, extractor, capabilities.matches)

        doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)

        # extract all MBS behaviors
        # taken from https://github.com/mandiant/capa/blob/master/scripts/capa_as_library.py
        if doc:
            for rule in rutils.capability_rules(doc):
                if not rule.meta.mbc:
                    continue
                for mbc in rule.meta.mbc:
                    if mbc.objective not in self.results:
                        self.results[mbc.objective] = []
                    self.results[mbc.objective].append(f"{mbc.id}: {mbc.behavior}::{mbc.method}")
        return len(self.results) > 0
