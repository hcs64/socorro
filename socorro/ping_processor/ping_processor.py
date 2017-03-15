import ujson
from configman import Namespace

from socorro.processor.processor_2015 import Processor2015
from socorro.lib.converters import change_default

# a processor to generate crash signatures from crash pings

ping_processor_rule_sets = [
    [   # rules to change the internals of the raw crash
        "raw_transform",
        "processor.json_rewrite",
        "socorro.lib.transform_rules.TransformRuleSystem",
        "apply_all_rules",
        "socorro.ping_processor.ping_transform_rules.RawCrashFromPing,"
        "socorro.processor.mozilla_transform_rules.ESRVersionRewrite,"
        "socorro.processor.mozilla_transform_rules.PluginContentURL,"
        "socorro.processor.mozilla_transform_rules.PluginUserComment,"
        "socorro.processor.mozilla_transform_rules.FennecBetaError20150430"
    ],
    [   # rules to transform a raw crash into a processed crash
        "raw_to_processed_transform",
        "processer.raw_to_processed",
        "socorro.lib.transform_rules.TransformRuleSystem",
        "apply_all_rules",
        "socorro.processor.general_transform_rules.IdentifierRule, "
        "socorro.ping_processor.ping_transform_rules.SymbolicatePingRule, "
        "socorro.processor.mozilla_transform_rules.ProductRule, "
        "socorro.processor.mozilla_transform_rules.UserDataRule, "
        "socorro.processor.mozilla_transform_rules.EnvironmentRule, "
        "socorro.processor.mozilla_transform_rules.PluginRule, "
        "socorro.processor.mozilla_transform_rules.AddonsRule, "
        "socorro.processor.mozilla_transform_rules.OutOfMemoryBinaryRule, "
        "socorro.processor.mozilla_transform_rules.JavaProcessRule, "
        "socorro.processor.mozilla_transform_rules.Winsock_LSPRule, "
    ],
    [   # post processing of the processed crash
        "processed_transform",
        "processer.processed",
        "socorro.lib.transform_rules.TransformRuleSystem",
        "apply_all_rules",
        "socorro.processor.breakpad_transform_rules.CrashingThreadRule, "
        "socorro.processor.general_transform_rules.OSInfoRule, "
        "socorro.processor.mozilla_transform_rules.BetaVersionRule, "
        "socorro.processor.mozilla_transform_rules.ExploitablityRule, "
        "socorro.processor.mozilla_transform_rules.FlashVersionRule, "
        "socorro.processor.mozilla_transform_rules.MissingSymbolsRule, "
        "socorro.processor.mozilla_transform_rules.ThemePrettyNameRule, "
        "socorro.processor.rules.memory_report_extraction"
        ".MemoryReportExtraction, "
        "socorro.processor.signature_utilities.SignatureGenerationRule,"
        "socorro.processor.signature_utilities.StackwalkerErrorSignatureRule, "
        "socorro.processor.signature_utilities.OOMSignature, "
        "socorro.processor.signature_utilities.AbortSignature, "
        "socorro.processor.signature_utilities.SignatureShutdownTimeout, "
        "socorro.processor.signature_utilities.SignatureRunWatchDog, "
        "socorro.processor.signature_utilities.SignatureIPCChannelError, "
        "socorro.processor.signature_utilities.SignatureIPCMessageName, "
        "socorro.processor.signature_utilities.SigTrim, "
        "socorro.processor.signature_utilities.SigTrunc, "
    ],
    # [   # a set of classifiers to help with jit crashes
    #     "jit_classifiers",
    #     "processor.jit_classifiers",
    #     "socorro.lib.transform_rules.TransformRuleSystem",
    #     "apply_all_rules",
    #     "socorro.processor.breakpad_transform_rules.JitCrashCategorizeRule, "
    #     "socorro.processor.signature_utilities.SignatureJitCategory, "
    # ]
]


# ==============================================================================
class PingProcessorAlgorithm(Processor2015):
    """this is the class that ping_processor uses to transform """

    required_config = Namespace()
    required_config.rule_sets = change_default(
        Processor2015,
        'rule_sets',
        ujson.dumps(ping_processor_rule_sets)
    )
