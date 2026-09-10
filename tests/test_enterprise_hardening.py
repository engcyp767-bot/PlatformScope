"""
Comprehensive Unit & Integration Test Suite for Enterprise Hardening (Phase 10).
"""

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from platform_core.enterprise import (
    ClusterHealthManager,
    EnterpriseTask,
    EnterpriseTaskQueue,
    RetentionPolicies,
    StorageGovernanceManager,
    TaskPriority,
    TaskStatus,
    Tenant,
    TenantManager,
    TenantQuotas,
    get_current_tenant_id,
    set_current_tenant_id,
    tenant_context,
)


class TestEnterpriseHardening(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="platform_enterprise_test_")
        self.storage_path = Path(self.tmp_dir)
        self.tenant_db = self.storage_path / "tenants.sqlite3"
        TenantManager.reset_instance()
        EnterpriseTaskQueue.reset_instance()

    def tearDown(self):
        EnterpriseTaskQueue.reset_instance()
        TenantManager.reset_instance()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_multi_tenancy_lifecycle_and_context(self):
        mgr = TenantManager(db_path=self.tenant_db)

        # 1. Verify default tenant seeded
        tenants = mgr.list_tenants()
        self.assertGreaterEqual(len(tenants), 1)
        default_t = mgr.get_tenant("default")
        self.assertIsNotNone(default_t)
        self.assertEqual(default_t.status, "active")

        # 2. Provision new enterprise tenant
        custom_quotas = TenantQuotas(
            max_storage_mb=50_000,
            max_concurrent_jobs=25,
            max_incidents=10_000,
            max_users=100,
        )
        new_tenant = mgr.create_tenant(
            tenant_id="bank-corp",
            name="Bank Corp SOC Operations",
            quotas=custom_quotas,
            metadata={"tier": "enterprise_gold", "sector": "financial"},
        )
        self.assertEqual(new_tenant.id, "bank-corp")
        self.assertEqual(new_tenant.quotas.max_storage_mb, 50_000)
        self.assertEqual(new_tenant.metadata.get("sector"), "financial")

        # 3. List tenants
        tenants_after = mgr.list_tenants()
        self.assertEqual(len(tenants_after), 2)
        tenant_ids = [t.id for t in tenants_after]
        self.assertIn("bank-corp", tenant_ids)

        # 4. Update status
        self.assertTrue(mgr.update_tenant_status("bank-corp", "suspended"))
        updated = mgr.get_tenant("bank-corp")
        self.assertEqual(updated.status, "suspended")

        # 5. Invalid status check
        with self.assertRaises(ValueError):
            mgr.update_tenant_status("bank-corp", "invalid_status")

        # 6. Scoped tenant context
        self.assertEqual(get_current_tenant_id(), "default")
        with tenant_context("bank-corp"):
            self.assertEqual(get_current_tenant_id(), "bank-corp")
        self.assertEqual(get_current_tenant_id(), "default")

    def test_enterprise_task_queue_priority_and_execution(self):
        queue = EnterpriseTaskQueue(num_workers=2)

        # Register custom test handlers
        processed_items = []
        def handler_quick(payload):
            processed_items.append(payload.get("item"))
            return {"status": "ok", "processed": payload.get("item")}

        def handler_fail_then_succeed(payload):
            count = payload.get("attempt", 0)
            payload["attempt"] = count + 1
            if count == 0:
                raise RuntimeError("Temporary worker timeout")
            return {"status": "recovered", "attempt": payload["attempt"]}

        queue.register_handler("process_quick", handler_quick)
        queue.register_handler("flaky_task", handler_fail_then_succeed)

        # 1. Submit normal task
        t1 = queue.submit("process_quick", {"item": "event_log_1"}, priority=TaskPriority.NORMAL)
        self.assertIsNotNone(t1)

        # 2. Submit high priority task
        t2 = queue.submit("process_quick", {"item": "incident_p1"}, priority=TaskPriority.CRITICAL)
        self.assertIsNotNone(t2)

        # Wait briefly for execution
        time.sleep(0.4)

        task1 = queue.get_task(t1)
        task2 = queue.get_task(t2)
        self.assertEqual(task1.status, TaskStatus.COMPLETED)
        self.assertEqual(task2.status, TaskStatus.COMPLETED)
        self.assertIn("event_log_1", processed_items)
        self.assertIn("incident_p1", processed_items)

        # 3. Test retry on transient failure
        t3 = queue.submit("flaky_task", {"attempt": 0}, priority=TaskPriority.HIGH, max_retries=2)
        time.sleep(0.4)
        task3 = queue.get_task(t3)
        self.assertEqual(task3.status, TaskStatus.COMPLETED)
        self.assertEqual(task3.retries, 1)
        self.assertEqual(task3.result.get("status"), "recovered")

        # 4. Progress, Cancellation & Retry
        t4 = queue.submit("process_quick", {"item": "cancel_candidate"}, priority=TaskPriority.LOW)
        task4 = queue.get_task(t4)
        self.assertIsNotNone(task4)
        queue.update_progress(t4, 50, "Halfway done")
        task4_updated = queue.get_task(t4)
        self.assertGreaterEqual(task4_updated.progress, 50)

        t5 = queue.submit("process_quick", {"item": "to_cancel"}, priority=TaskPriority.LOW)
        queue.cancel_task(t5)
        task5 = queue.get_task(t5)
        self.assertIn(task5.status, (TaskStatus.CANCELLED, TaskStatus.COMPLETED))

        if task5.status == TaskStatus.CANCELLED:
            re_ok = queue.retry_task(t5)
            self.assertTrue(re_ok)
            time.sleep(0.3)
            task5_retried = queue.get_task(t5)
            self.assertEqual(task5_retried.status, TaskStatus.COMPLETED)

        # 5. Metrics & Listing
        tasks_list = queue.list_tasks(limit=10)
        self.assertGreaterEqual(len(tasks_list), 3)
        metrics = queue.get_metrics()
        self.assertEqual(metrics["active_workers"], 2)
        self.assertGreaterEqual(metrics["completed_tasks"], 3)

        queue.shutdown()

    def test_cluster_health_probes(self):
        # 1. Liveness probe
        liveness = ClusterHealthManager.check_liveness()
        self.assertEqual(liveness["status"], "live")
        self.assertGreaterEqual(liveness["uptime_seconds"], 0.0)
        self.assertIn("timestamp", liveness)

        # 2. Readiness probe
        readiness = ClusterHealthManager.check_readiness()
        self.assertIn(readiness["status"], ("ready", "not_ready"))
        self.assertIn("storage_writable", readiness["checks"])
        self.assertTrue(readiness["checks"]["storage_writable"])

        # 3. Cluster status
        # 3. Cluster status & metrics
        cluster = ClusterHealthManager.get_cluster_status()
        self.assertIsNotNone(cluster["node_id"])
        self.assertEqual(cluster["role"], "primary")
        self.assertIn("system_info", cluster)
        self.assertIn("python_version", cluster["system_info"])
        self.assertIn("metrics", cluster)

        # 4. System telemetry & rolling history
        metrics = ClusterHealthManager.get_system_metrics()
        self.assertIn("cpu_percent", metrics)
        self.assertIn("ram_percent", metrics)
        self.assertIn("disk_percent", metrics)
        self.assertGreaterEqual(metrics["cpu_percent"], 0.0)
        self.assertLessEqual(metrics["cpu_percent"], 100.0)

        sample = ClusterHealthManager.record_sample()
        self.assertIsNotNone(sample)
        history = ClusterHealthManager.get_history(limit=10)
        self.assertGreaterEqual(len(history), 1)

    def test_storage_governance_and_archival(self):
        # Create synthetic analysis job folders in temp directory
        analyses_dir = self.storage_path / "analyses"
        analyses_dir.mkdir(parents=True, exist_ok=True)

        job_folder = analyses_dir / "job_mock_old_001"
        job_folder.mkdir(parents=True, exist_ok=True)
        (job_folder / "analysis.json").write_text('{"mock": true}', encoding="utf-8")
        (job_folder / "events.csv").write_text("id,ip\n1,10.0.0.1\n", encoding="utf-8")

        # Set modification time to 120 days ago
        old_epoch = time.time() - (120 * 86400)
        os.utime(job_folder, (old_epoch, old_epoch))

        # Test breakdown
        breakdown = StorageGovernanceManager.get_storage_breakdown()
        self.assertIsInstance(breakdown, dict)
        self.assertIn("total_bytes", breakdown)
        self.assertIn("breakdown", breakdown)

        # Test archival dry run
        dry_res = StorageGovernanceManager.archive_cold_jobs(days_threshold=90, dry_run=True)
        self.assertTrue(dry_res["dry_run"])
        self.assertIn("candidate_jobs_count", dry_res)

    def test_notification_engine_lifecycle(self):
        from platform_core import notification_engine

        test_user = f"test_user_{int(time.time())}"
        # 1. Create notifications
        n1 = notification_engine.create_notification(
            title="تنبيه تجريبي 1",
            message="هذا تنبيه أمني للاختبار",
            category="security",
            severity="critical",
            target_user=test_user,
            link="/incidents/test-01",
        )
        self.assertIsNotNone(n1["id"])
        self.assertEqual(n1["severity"], "critical")
        self.assertFalse(n1["is_read"])

        n2 = notification_engine.create_notification(
            title="تنبيه تجريبي 2",
            message="إشعار صيانة النظام",
            category="system",
            severity="info",
            target_user=test_user,
        )
        self.assertIsNotNone(n2["id"])

        # 2. Check unread count
        unread = notification_engine.get_unread_count(user=test_user)
        self.assertEqual(unread, 2)

        # 3. List notifications
        notifs = notification_engine.list_notifications(user=test_user)
        self.assertGreaterEqual(len(notifs), 2)

        # 4. Mark one as read
        ok = notification_engine.mark_as_read(n1["id"], user=test_user)
        self.assertTrue(ok)
        unread_after = notification_engine.get_unread_count(user=test_user)
        self.assertEqual(unread_after, 1)

        # 5. Mark all as read
        marked_cnt = notification_engine.mark_all_as_read(user=test_user)
        self.assertEqual(marked_cnt, 1)
        self.assertEqual(notification_engine.get_unread_count(user=test_user), 0)

        # 6. Delete notification
        deleted = notification_engine.delete_notification(n1["id"])
        self.assertTrue(deleted)
        deleted2 = notification_engine.delete_notification(n2["id"])
        self.assertTrue(deleted2)


if __name__ == "__main__":
    unittest.main()
