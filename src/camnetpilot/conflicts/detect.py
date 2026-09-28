"""Détection et résolution de conflits d'adresses IP au niveau L2 (section 5)."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any

from ..models import Camera, Conflict, ResolutionStatus

logger = logging.getLogger("camnetpilot.conflicts")


def detect_conflicts(cameras: list[Camera]) -> list[Conflict]:
    """Détecte les conflits d'adresses IP parmi les caméras découvertes.

    Retourne une liste de Conflict, un par adresse IP en conflit (partagée par ≥ 2 caméras).
    """
    ip_to_macs: dict[str, list[str]] = {}
    for cam in cameras:
        ip_to_macs.setdefault(cam.ip_address, []).append(cam.mac_address)

    conflicts: list[Conflict] = []
    for ip, macs in ip_to_macs.items():
        if len(macs) >= 2:
            for cam in [c for c in cameras if c.ip_address == ip]:
                cam.has_conflict = True
            conflicts.append(
                Conflict(
                    conflicting_ip=ip,
                    camera_macs=macs,
                )
            )
    return conflicts


@dataclass
class _ConflictResolutionResult:
    """Résultat interne de résolution d'un conflit."""
    success: bool
    temp_ips: dict[str, str]  # mac -> temp_ip
    error: str | None = None


def resolve_conflict(
    conflict: Conflict,
    cameras_by_mac: dict[str, Camera],
    announcer: Any,
    subnet_mask: str,
    reserved_ips: set[str],
) -> Conflict:
    """Résout un conflit d'adresse IP en attribuant des IP temporaires uniques.

    La stratégie :
    1. Détermine un sous-réseau de travail (IP du conflit + masque)
    2. Itère sur les IPs disponibles du sous-réseau (hors réservées et IP du conflit)
    3. Pour chaque MAC en conflit, tente d'attribuer une IP libre via le canal MAC-adressé
    4. Met à jour la table ARP via l'annonceur

    Retourne le conflit mis à jour avec son statut de résolution.
    """
    network = ipaddress.IPv4Network(f"{conflict.conflicting_ip}/{subnet_mask}", strict=False)
    reserved = set(reserved_ips)
    reserved.add(conflict.conflicting_ip)

    # Génère la liste des IPs candidates (hors réservées et IP du conflit)
    candidate_ips = [str(ip) for ip in network.hosts() if str(ip) not in reserved]

    macs = conflict.camera_macs
    temp_assignments: dict[str, str] = {}  # mac -> temp_ip

    for i, mac in enumerate(macs):
        if i >= len(candidate_ips):
            logger.error("Pas assez d'IPs libres pour résoudre le conflit %s", conflict.conflicting_ip)
            conflict.resolution_status = ResolutionStatus.FAILED
            conflict.resolution_detail = "Pas assez d'IPs libres dans le sous-réseau"
            return conflict

        temp_ip = candidate_ips[i]
        mac = macs[i]

        # Tente de réassigner l'IP via le canal MAC-adressé
        success = False
        try:
            # Tente de réassigner via le canal MAC-adressé
            success = announcer.set_ip_by_mac(conflict.camera_macs[i], str(candidate_ips[i]))
        except Exception as e:
            logger.warning("Échec réassignation IP pour %s: %s", conflict.camera_macs[i], e)

        if success:
            temp_assignments[conflict.camera_macs[i]] = candidate_ips[i]
        else:
            logger.error("Échec réassignation IP pour %s", conflict.camera_macs[i])

    # Vérifie que toutes les MACs ont reçu une IP
    if len(temp_assignments) == len(macs):
        conflict.resolution_status = ResolutionStatus.RESOLVED
        conflict.resolution_method = "mac_addressed_broadcast"
        conflict.resolution_detail = f"IPs temporaires attribuées : {temp_assignments}"
    else:
        conflict.resolution_status = ResolutionStatus.FAILED
        conflict.resolution_detail = "Échec attribution IP temporaire pour au moins une MAC"

    return conflict


def detect_conflicts(cameras: list[Camera]) -> list:
    """Détecte les conflits d'adresses IP parmi les caméras découvertes.

    Retourne une liste de Conflict, un par adresse IP en conflit (partagée par ≥ 2 caméras).
    """
    ip_to_macs: dict[str, list[str]] = {}
    for cam in cameras:
        ip_to_macs.setdefault(cam.ip_address, []).append(cam.mac_address)

    conflicts: list = []
    for ip, macs in ip_to_macs.items():
        if len(macs) >= 2:
            for cam in [c for c in cameras if c.ip_address == ip]:
                cam.has_conflict = True
            conflicts.append(
                Conflict(
                    conflicting_ip=ip,
                    camera_macs=macs,
                )
            )
    return conflicts


__all__ = ["detect_conflicts", "resolve_conflict"]