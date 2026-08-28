"""
Unit tests for Automated Evaluation CI, Model Registry & Active Learning Feedback Loop
"""

import os
import unittest
from evaluation.ci_eval_runner import run_ci_evaluation
from core.compliance_engine import compliance_engine
from core.async_pipeline import pipeline_manager
import core.model_registry as model_reg
import core.feedback_collector as feedback_col


class TestComplianceCIEvaluation(unittest.TestCase):
    
    def test_ci_eval_benchmark_runner(self):
        """Validates that automated CI benchmark runner achieves >= 80% accuracy and Ragas metrics."""
        report = run_ci_evaluation()
        self.assertEqual(report["status"], "PASSED")
        self.assertGreaterEqual(report["total_standards_tested"], 16)
        self.assertGreaterEqual(report["standards_coverage_count"], 16)
        self.assertGreaterEqual(report["router_accuracy_pct"], 80.0)
        self.assertGreaterEqual(report["intent_accuracy_pct"], 80.0)
        self.assertGreaterEqual(report["avg_faithfulness_pct"], 75.0)
        self.assertGreaterEqual(report["avg_control_recall_pct"], 80.0)
        self.assertTrue(report["grounding_check"]["grounded"])

    def test_model_registry_operations(self):
        """Validates SQLite model registry scanning, versioning, and adapter metrics."""
        models = model_reg.get_all_registered_models()
        self.assertGreaterEqual(len(models), 10)
        
        # Verify first model metadata schema
        m = models[0]
        self.assertIn("adapter_name", m)
        self.assertIn("base_model", m)
        self.assertIn("lora_rank", m)
        self.assertIn("param_count_mb", m)
        self.assertEqual(m["status"], "Active")

    def test_active_learning_feedback_collector(self):
        """Validates auditor feedback capture, statistics, and dataset JSONL export."""
        ok = feedback_col.record_feedback(
            query="Test compliance breach rule",
            response="Breaches must be reported in 72 hours under GDPR Art 33",
            rating=1,
            session_id="test_session_ci",
            username="ci_auditor",
            framework="eu/gdpr"
        )
        self.assertTrue(ok)
        
        stats = feedback_col.get_feedback_statistics()
        self.assertGreaterEqual(stats["total_reviews"], 1)
        self.assertGreaterEqual(stats["positive_count"], 1)

        # Test export
        tmp_export = "logs/test_feedback_export.jsonl"
        count, path = feedback_col.export_feedback_to_dataset(tmp_export)
        self.assertTrue(os.path.exists(path))
        if os.path.exists(tmp_export):
            os.remove(tmp_export)

        # Test SFT corrections export
        ok_neg = feedback_col.record_feedback(
            query="What is GDPR Article 33 deadline?",
            response="30 days",
            rating=-1,
            remediation_text="72 hours from becoming aware of the breach",
            session_id="test_sft_ci",
            username="ci_auditor",
            framework="eu/gdpr"
        )
        self.assertTrue(ok_neg)

        sft_export = "logs/test_sft_export.jsonl"
        sft_cnt, sft_path = feedback_col.export_sft_corrections(output_path=sft_export)
        self.assertGreaterEqual(sft_cnt, 1)
        self.assertTrue(os.path.exists(sft_path))
        if os.path.exists(sft_export):
            os.remove(sft_export)

        # Test DPO pairs export
        dpo_export = "logs/test_dpo_export.jsonl"
        dpo_cnt, dpo_path = feedback_col.export_dpo_pairs(output_path=dpo_export)
        self.assertGreaterEqual(dpo_cnt, 1)
        self.assertTrue(os.path.exists(dpo_path))
        if os.path.exists(dpo_export):
            os.remove(dpo_export)

    def test_reward_model_scorer(self):
        """Validates Agent 9 Reward Model scoring accuracy and refusal penalty."""
        from agents import agent9_reward_model
        
        # High quality response with compliance keywords and retrieved source
        score_good = agent9_reward_model.score_response(
            query="What are GDPR principles?",
            response="GDPR Article 5 outlines compliance requirements for data minimization, purpose limitation, and accountability.",
            framework="gdpr",
            sources=["GDPR Article 5 outlines principles relating to processing of personal data."]
        )
        self.assertGreaterEqual(score_good["reward_score"], 0.6)
        self.assertIn(score_good["verdict"], ["ACCEPT", "MARGINAL"])

        # Poor / evasive response
        score_bad = agent9_reward_model.score_response(
            query="What are GDPR principles?",
            response="I do not have access and as an AI language model I cannot browse.",
            framework="gdpr"
        )
        self.assertLessEqual(score_bad["reward_score"], 0.45)
        self.assertEqual(score_bad["verdict"], "REJECT")

    def test_active_learning_orchestrator_status(self):
        """Validates Agent 10 continuous alignment status calculation."""
        from agents import agent10_active_learning
        st = agent10_active_learning.get_alignment_status()
        self.assertIn("overall", st)
        self.assertIn("frameworks", st)
        self.assertGreaterEqual(st["overall"]["total_reviews"], 1)

    def test_compliance_engine_routing(self):
        """Validates decoupled compliance engine routing and metadata generation."""
        res = compliance_engine.execute_compliance_query("How does GDPR require consent to be handled?")
        self.assertEqual(res["routed_framework"], "eu/gdpr")
        self.assertIn("use_self_healing", res)
        self.assertEqual(res["status"], "ready")

    def test_async_pipeline_manager(self):
        """Validates async pipeline execution and background worker submission."""
        def dummy_worker(x, y):
            return x + y

        future = pipeline_manager.submit_task("test_task_1", dummy_worker, 10, 20)
        res = future.result()
        self.assertEqual(res, 30)
        
        status = pipeline_manager.get_task_status("test_task_1")
        self.assertIsNotNone(status)
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["result"], 30)


if __name__ == "__main__":
    unittest.main()

