
// Description: Java 11 in-memory RAM DbIO implementation for SecGroup.

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2020 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFSec 2.13 Security Essentials
 *	
 *	Copyright 2020-2021 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfint.CFIntRam;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;
import org.msscf.msscf.v2_13.cfint.CFInt.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;
import org.msscf.msscf.v2_13.cfsec.CFSecObj.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;

/*
 *	CFIntRamSecGroupTable in-memory RAM DbIO implementation
 *	for SecGroup.
 */
public class CFIntRamSecGroupTable
	implements ICFIntSecGroupTable
{
	private ICFIntSchema schema;
	private Map< CFSecSecGroupPKey,
				CFSecSecGroupBuff > dictByPKey
		= new HashMap< CFSecSecGroupPKey,
				CFSecSecGroupBuff >();
	private Map< CFSecSecGroupByClusterIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >> dictByClusterIdx
		= new HashMap< CFSecSecGroupByClusterIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >>();
	private Map< CFSecSecGroupByClusterVisIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >> dictByClusterVisIdx
		= new HashMap< CFSecSecGroupByClusterVisIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >>();
	private Map< CFSecSecGroupByUNameIdxKey,
			CFSecSecGroupBuff > dictByUNameIdx
		= new HashMap< CFSecSecGroupByUNameIdxKey,
			CFSecSecGroupBuff >();

	public CFIntRamSecGroupTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecGroup( CFSecAuthorization Authorization,
		CFSecSecGroupBuff Buff )
	{
		final String S_ProcName = "createSecGroup";
		CFSecSecGroupPKey pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGroupId( ((CFIntRamClusterTable)schema.getTableCluster()).nextSecGroupIdGen( Authorization,
			Buff.getRequiredClusterId() ) );
		Buff.setRequiredClusterId( pkey.getRequiredClusterId() );
		Buff.setRequiredSecGroupId( pkey.getRequiredSecGroupId() );
		CFSecSecGroupByClusterIdxKey keyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGroupByClusterVisIdxKey keyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		keyClusterVisIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyClusterVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecSecGroupByUNameIdxKey keyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecGroupUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"SecGroupCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterVisIdx;
		if( dictByClusterVisIdx.containsKey( keyClusterVisIdx ) ) {
			subdictClusterVisIdx = dictByClusterVisIdx.get( keyClusterVisIdx );
		}
		else {
			subdictClusterVisIdx = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterVisIdx.put( keyClusterVisIdx, subdictClusterVisIdx );
		}
		subdictClusterVisIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

	}

	public CFSecSecGroupBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGroup.readDerived";
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecGroupId( PKey.getRequiredSecGroupId() );
		CFSecSecGroupBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGroup.readDerived";
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecGroupId( PKey.getRequiredSecGroupId() );
		CFSecSecGroupBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamSecGroup.readAllDerived";
		CFSecSecGroupBuff[] retList = new CFSecSecGroupBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecGroupBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecGroupBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecGroup.readDerivedByClusterIdx";
		CFSecSecGroupByClusterIdxKey key = schema.getFactorySecGroup().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSecGroupBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSecGroupBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSecGroupBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterIdx
				= new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSecGroupBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupBuff[] readDerivedByClusterVisIdx( CFSecAuthorization Authorization,
		long ClusterId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFIntRamSecGroup.readDerivedByClusterVisIdx";
		CFSecSecGroupByClusterVisIdxKey key = schema.getFactorySecGroup().newClusterVisIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredIsVisible( IsVisible );

		CFSecSecGroupBuff[] recArray;
		if( dictByClusterVisIdx.containsKey( key ) ) {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterVisIdx
				= dictByClusterVisIdx.get( key );
			recArray = new CFSecSecGroupBuff[ subdictClusterVisIdx.size() ];
			Iterator< CFSecSecGroupBuff > iter = subdictClusterVisIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterVisIdx
				= new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterVisIdx.put( key, subdictClusterVisIdx );
			recArray = new CFSecSecGroupBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupBuff readDerivedByUNameIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String Name )
	{
		final String S_ProcName = "CFIntRamSecGroup.readDerivedByUNameIdx";
		CFSecSecGroupByUNameIdxKey key = schema.getFactorySecGroup().newUNameIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredName( Name );

		CFSecSecGroupBuff buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId )
	{
		final String S_ProcName = "CFIntRamSecGroup.readDerivedByIdIdx() ";
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );

		CFSecSecGroupBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGroup.readBuff";
		CFSecSecGroupBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00c" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecGroupBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00c" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamSecGroup.readAllBuff";
		CFSecSecGroupBuff buff;
		ArrayList<CFSecSecGroupBuff> filteredList = new ArrayList<CFSecSecGroupBuff>();
		CFSecSecGroupBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupBuff[0] ) );
	}

	public CFSecSecGroupBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId )
	{
		final String S_ProcName = "CFIntRamSecGroup.readBuffByIdIdx() ";
		CFSecSecGroupBuff buff = readDerivedByIdIdx( Authorization,
			ClusterId,
			SecGroupId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
			return( (CFSecSecGroupBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecGroupBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecGroup.readBuffByClusterIdx() ";
		CFSecSecGroupBuff buff;
		ArrayList<CFSecSecGroupBuff> filteredList = new ArrayList<CFSecSecGroupBuff>();
		CFSecSecGroupBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( (CFSecSecGroupBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupBuff[0] ) );
	}

	public CFSecSecGroupBuff[] readBuffByClusterVisIdx( CFSecAuthorization Authorization,
		long ClusterId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFIntRamSecGroup.readBuffByClusterVisIdx() ";
		CFSecSecGroupBuff buff;
		ArrayList<CFSecSecGroupBuff> filteredList = new ArrayList<CFSecSecGroupBuff>();
		CFSecSecGroupBuff[] buffList = readDerivedByClusterVisIdx( Authorization,
			ClusterId,
			IsVisible );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( (CFSecSecGroupBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupBuff[0] ) );
	}

	public CFSecSecGroupBuff readBuffByUNameIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String Name )
	{
		final String S_ProcName = "CFIntRamSecGroup.readBuffByUNameIdx() ";
		CFSecSecGroupBuff buff = readDerivedByUNameIdx( Authorization,
			ClusterId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
			return( (CFSecSecGroupBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateSecGroup( CFSecAuthorization Authorization,
		CFSecSecGroupBuff Buff )
	{
		CFSecSecGroupPKey pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		CFSecSecGroupBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecGroup",
				"Existing record not found",
				"SecGroup",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecGroup",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecGroupByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGroupByClusterIdxKey newKeyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGroupByClusterVisIdxKey existingKeyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		existingKeyClusterVisIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyClusterVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecSecGroupByClusterVisIdxKey newKeyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		newKeyClusterVisIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyClusterVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecSecGroupByUNameIdxKey existingKeyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		existingKeyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecSecGroupByUNameIdxKey newKeyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		newKeyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecGroup",
					"SecGroupUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecGroup",
						"Container",
						"SecGroupCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByClusterVisIdx.get( existingKeyClusterVisIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterVisIdx.containsKey( newKeyClusterVisIdx ) ) {
			subdict = dictByClusterVisIdx.get( newKeyClusterVisIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterVisIdx.put( newKeyClusterVisIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

	}

	public void deleteSecGroup( CFSecAuthorization Authorization,
		CFSecSecGroupBuff Buff )
	{
		final String S_ProcName = "CFIntRamSecGroupTable.deleteSecGroup() ";
		String classCode;
		CFSecSecGroupPKey pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		CFSecSecGroupBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecGroup",
				pkey );
		}
					schema.getTableSecGroupForm().deleteSecGroupFormByGroupIdx( Authorization,
						existing.getRequiredClusterId(),
						existing.getRequiredSecGroupId() );
					schema.getTableSecGrpInc().deleteSecGrpIncByIncludeIdx( Authorization,
						existing.getRequiredClusterId(),
						existing.getRequiredSecGroupId() );
					schema.getTableSecGrpMemb().deleteSecGrpMembByGroupIdx( Authorization,
						existing.getRequiredClusterId(),
						existing.getRequiredSecGroupId() );
					schema.getTableSecGrpInc().deleteSecGrpIncByGroupIdx( Authorization,
						existing.getRequiredClusterId(),
						existing.getRequiredSecGroupId() );
		CFSecSecGroupByClusterIdxKey keyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGroupByClusterVisIdxKey keyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		keyClusterVisIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyClusterVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecSecGroupByUNameIdxKey keyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByClusterVisIdx.get( keyClusterVisIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	public void deleteSecGroupByIdIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecGroupId )
	{
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGroupByIdIdx( Authorization, key );
	}

	public void deleteSecGroupByIdIdx( CFSecAuthorization Authorization,
		CFSecSecGroupPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecGroupBuff cur;
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSecGroupByClusterIdxKey key = schema.getFactorySecGroup().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGroupByClusterIdx( Authorization, key );
	}

	public void deleteSecGroupByClusterIdx( CFSecAuthorization Authorization,
		CFSecSecGroupByClusterIdxKey argKey )
	{
		CFSecSecGroupBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByClusterVisIdx( CFSecAuthorization Authorization,
		long argClusterId,
		boolean argIsVisible )
	{
		CFSecSecGroupByClusterVisIdxKey key = schema.getFactorySecGroup().newClusterVisIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredIsVisible( argIsVisible );
		deleteSecGroupByClusterVisIdx( Authorization, key );
	}

	public void deleteSecGroupByClusterVisIdx( CFSecAuthorization Authorization,
		CFSecSecGroupByClusterVisIdxKey argKey )
	{
		CFSecSecGroupBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByUNameIdx( CFSecAuthorization Authorization,
		long argClusterId,
		String argName )
	{
		CFSecSecGroupByUNameIdxKey key = schema.getFactorySecGroup().newUNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredName( argName );
		deleteSecGroupByUNameIdx( Authorization, key );
	}

	public void deleteSecGroupByUNameIdx( CFSecAuthorization Authorization,
		CFSecSecGroupByUNameIdxKey argKey )
	{
		CFSecSecGroupBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
