"""POS service -- terminal registration, transactions, fraud detection."""

import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.pos.models import FraudAlert, SettlementBatch, Terminal, Transaction

_DB_KEY = "transaction"
_FRAUD_THRESHOLD = 10_000
_VELOCITY_WINDOW_SECONDS = 60
_VELOCITY_MAX = 5


class POSService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def register_terminal(
        self, name: str, location: str = "", device_type: str = ""
    ) -> dict:
        if not name:
            raise ValidationError("Terminal name must not be empty")
        async with self.db.get_session(_DB_KEY) as session:
            terminal = Terminal(name=name, location=location, device_type=device_type)
            session.add(terminal)
            await session.flush()
        return {
            "id": terminal.id,
            "name": terminal.name,
            "location": terminal.location,
            "is_active": terminal.is_active,
            "device_type": terminal.device_type,
        }

    async def create_transaction(
        self, terminal_id: str, amount: float, currency: str = "USD"
    ) -> dict:
        if amount <= 0:
            raise ValidationError("Amount must be positive")

        async with self.db.get_session(_DB_KEY) as session:
            # Verify terminal exists and is active
            result = await session.execute(
                select(Terminal).where(
                    Terminal.id == terminal_id, Terminal.is_active == True
                )
            )
            if result.scalar_one_or_none() is None:
                raise NotFoundError("Active terminal not found")

            reference = f"TXN-{os.urandom(8).hex()}"
            txn = Transaction(
                terminal_id=terminal_id,
                amount=amount,
                currency=currency,
                status="completed",
                reference=reference,
            )
            session.add(txn)
            await session.flush()

            # Multi-signal fraud scoring
            risk_score, signals = await self._score_fraud(
                session, terminal_id, amount, currency
            )

            for signal in signals:
                alert = FraudAlert(
                    transaction_id=txn.id,
                    alert_type=signal["type"],
                    severity=signal["severity"],
                    detail=signal["detail"],
                )
                session.add(alert)

        return {
            "id": txn.id,
            "terminal_id": txn.terminal_id,
            "amount": txn.amount,
            "currency": txn.currency,
            "status": txn.status,
            "reference": txn.reference,
            "risk_score": round(risk_score, 3),
        }

    async def _score_fraud(
        self, session, terminal_id: str, amount: float, currency: str
    ) -> tuple[float, list[dict]]:
        """Score a transaction for fraud risk. Returns (risk_score, signals)."""
        score = 0.0
        signals = []

        # Signal 1: High amount threshold
        if amount > _FRAUD_THRESHOLD:
            score += 0.4
            signals.append({
                "type": "high_amount",
                "severity": "high",
                "detail": f"Amount {amount} exceeds threshold {_FRAUD_THRESHOLD}",
            })

        # Signal 2: Velocity — too many transactions from same terminal in window
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_VELOCITY_WINDOW_SECONDS)
        result = await session.execute(
            select(func.count()).select_from(Transaction).where(
                Transaction.terminal_id == terminal_id,
                Transaction.created_at >= cutoff,
            )
        )
        recent_count = result.scalar() or 0
        if recent_count > _VELOCITY_MAX:
            score += 0.3
            signals.append({
                "type": "velocity",
                "severity": "medium",
                "detail": f"{recent_count} transactions in {_VELOCITY_WINDOW_SECONDS}s window",
            })

        # Signal 3: Round amount pattern (exact multiples of 1000 above 1000)
        if amount >= 1000 and amount == int(amount) and amount % 1000 == 0:
            score += 0.15
            signals.append({
                "type": "round_amount",
                "severity": "low",
                "detail": f"Exact round amount {amount}",
            })

        # Signal 4: Currency mismatch with terminal's prior transactions
        result = await session.execute(
            select(Transaction.currency).where(
                Transaction.terminal_id == terminal_id,
            ).limit(1)
        )
        first_currency = result.scalar_one_or_none()
        if first_currency and first_currency != currency:
            score += 0.2
            signals.append({
                "type": "currency_mismatch",
                "severity": "medium",
                "detail": f"Currency {currency} differs from terminal's usual {first_currency}",
            })

        return min(score, 1.0), signals

    async def get_fraud_alerts(self, resolved: bool | None = None) -> list[dict]:
        async with self.db.get_session(_DB_KEY) as session:
            stmt = select(FraudAlert)
            if resolved is not None:
                stmt = stmt.where(FraudAlert.resolved == resolved)
            result = await session.execute(stmt)
            alerts = result.scalars().all()
        return [
            {
                "id": a.id,
                "transaction_id": a.transaction_id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "detail": a.detail,
                "resolved": a.resolved,
            }
            for a in alerts
        ]

    # ── Settlement & Reconciliation ──

    async def create_settlement(self, terminal_id: str) -> dict:
        """Batch all unsettled transactions for a terminal into a settlement."""
        async with self.db.get_session(_DB_KEY) as session:
            # Verify terminal exists
            result = await session.execute(
                select(Terminal).where(Terminal.id == terminal_id)
            )
            if result.scalar_one_or_none() is None:
                raise NotFoundError("Terminal not found")

            # Get completed unsettled transactions
            result = await session.execute(
                select(Transaction).where(
                    Transaction.terminal_id == terminal_id,
                    Transaction.status == "completed",
                )
            )
            txns = result.scalars().all()
            if not txns:
                raise ValidationError("No unsettled transactions for this terminal")

            total = sum(t.amount for t in txns)
            currency = txns[0].currency

            batch = SettlementBatch(
                terminal_id=terminal_id,
                transaction_count=len(txns),
                total_amount=round(total, 2),
                currency=currency,
                status="settled",
                reference=f"STL-{os.urandom(8).hex()}",
            )
            session.add(batch)

            # Mark transactions as settled
            for txn in txns:
                txn.status = "settled"

            await session.flush()

        return {
            "id": batch.id,
            "terminal_id": batch.terminal_id,
            "transaction_count": batch.transaction_count,
            "total_amount": batch.total_amount,
            "currency": batch.currency,
            "status": batch.status,
            "reference": batch.reference,
        }

    async def get_settlement(self, settlement_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SettlementBatch).where(SettlementBatch.id == settlement_id)
            )
            batch = result.scalar_one_or_none()
            if batch is None:
                raise NotFoundError("Settlement not found")

        return {
            "id": batch.id,
            "terminal_id": batch.terminal_id,
            "transaction_count": batch.transaction_count,
            "total_amount": batch.total_amount,
            "currency": batch.currency,
            "status": batch.status,
            "reference": batch.reference,
        }

    async def reconcile(self, terminal_id: str) -> dict:
        """Reconcile: compare settled batches with transaction totals."""
        async with self.db.get_session(_DB_KEY) as session:
            # Get total from settled batches
            result = await session.execute(
                select(func.sum(SettlementBatch.total_amount)).where(
                    SettlementBatch.terminal_id == terminal_id,
                    SettlementBatch.status == "settled",
                )
            )
            batch_total = result.scalar() or 0.0

            # Get total from settled transactions
            result = await session.execute(
                select(func.sum(Transaction.amount)).where(
                    Transaction.terminal_id == terminal_id,
                    Transaction.status == "settled",
                )
            )
            txn_total = result.scalar() or 0.0

            discrepancy = round(abs(batch_total - txn_total), 2)

        return {
            "terminal_id": terminal_id,
            "batch_total": round(batch_total, 2),
            "transaction_total": round(txn_total, 2),
            "discrepancy": discrepancy,
            "reconciled": discrepancy == 0.0,
        }
