<?php

namespace Siberfx\RiskAnalyzer;

enum Category: string
{
    case Code = 'code';
    case Runtime = 'runtime';
    case Dependencies = 'dependencies';
    case Filesystem = 'filesystem';

    public function label(): string
    {
        return match ($this) {
            self::Code => 'Code',
            self::Runtime => 'Configuration & routes',
            self::Dependencies => 'Dependencies',
            self::Filesystem => 'Filesystem',
        };
    }
}
