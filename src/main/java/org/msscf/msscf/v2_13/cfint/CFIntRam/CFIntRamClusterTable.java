
// Description: Java 11 in-memory RAM DbIO implementation for Cluster.

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
 *	CFIntRamClusterTable in-memory RAM DbIO implementation
 *	for Cluster.
 */
public class CFIntRamClusterTable
	implements ICFIntClusterTable
{
	private ICFIntSchema schema;
	private Map< CFSecClusterPKey,
				CFSecClusterBuff > dictByPKey
		= new HashMap< CFSecClusterPKey,
				CFSecClusterBuff >();
	private Map< CFSecClusterByUDomNameIdxKey,
			CFSecClusterBuff > dictByUDomNameIdx
		= new HashMap< CFSecClusterByUDomNameIdxKey,
			CFSecClusterBuff >();
	private Map< CFSecClusterByUDescrIdxKey,
			CFSecClusterBuff > dictByUDescrIdx
		= new HashMap< CFSecClusterByUDescrIdxKey,
			CFSecClusterBuff >();
	private Map< CFIntRamClusterId32Gen,
				CFIntRamClusterId32Gen > id32Generator
		= new HashMap< CFIntRamClusterId32Gen,
				CFIntRamClusterId32Gen >();
	private Map< CFIntRamClusterId64Gen,
				CFIntRamClusterId64Gen > id64Generator
		= new HashMap< CFIntRamClusterId64Gen,
				CFIntRamClusterId64Gen >();

	public CFIntRamClusterTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	protected int generateNextId32( long argId,
		short argSliceId )
	{
		CFIntRamClusterId32Gen key = new CFIntRamClusterId32Gen();
		key.setRequiredId( argId );
		key.setRequiredSliceId( argSliceId );

		CFIntRamClusterId32Gen useGen = id32Generator.get( key );
		if( useGen == null ) {
			id32Generator.put( key, key );
			useGen = key;
		}

		int retNext = useGen.getNextId();

		return( retNext );
	}

	protected long generateNextId64( long argId,
		short argSliceId )
	{
		CFIntRamClusterId64Gen key = new CFIntRamClusterId64Gen();
		key.setRequiredId( argId );
		key.setRequiredSliceId( argSliceId );

		CFIntRamClusterId64Gen useGen = id64Generator.get( key );
		if( useGen == null ) {
			id64Generator.put( key, key );
			useGen = key;
		}

		long retNext = useGen.getNextId();

		return( retNext );
	}

	public int nextSecAppIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		int retval = nextSecAppIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public int nextSecAppIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		int retNext = generateNextId32( argId,
			(short)107 );
		return( retNext );
	}

	public int nextSecFormIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		int retval = nextSecFormIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public int nextSecFormIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		int retNext = generateNextId32( argId,
			(short)108 );
		return( retNext );
	}

	public int nextSecGroupIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		int retval = nextSecGroupIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public int nextSecGroupIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		int retNext = generateNextId32( argId,
			(short)109 );
		return( retNext );
	}

	public long nextHostNodeIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		long retval = nextHostNodeIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public long nextHostNodeIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		long retNext = generateNextId64( argId,
			(short)116 );
		return( retNext );
	}

	public long nextSecGroupFormIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		long retval = nextSecGroupFormIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public long nextSecGroupFormIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		long retNext = generateNextId64( argId,
			(short)112 );
		return( retNext );
	}

	public long nextSecGrpIncIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		long retval = nextSecGrpIncIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public long nextSecGrpIncIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		long retNext = generateNextId64( argId,
			(short)111 );
		return( retNext );
	}

	public long nextSecGrpMembIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		long retval = nextSecGrpMembIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public long nextSecGrpMembIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		long retNext = generateNextId64( argId,
			(short)110 );
		return( retNext );
	}

	public long nextServiceIdGen( CFSecAuthorization Authorization,
		CFSecClusterPKey pkey )
	{
		long retval = nextServiceIdGen( Authorization,
			pkey.getRequiredId() );
		return( retval );
	}

	public long nextServiceIdGen( CFSecAuthorization Authorization,
		long argId )
	{
		long retNext = generateNextId64( argId,
			(short)115 );
		return( retNext );
	}

	public void createCluster( CFSecAuthorization Authorization,
		CFSecClusterBuff Buff )
	{
		final String S_ProcName = "createCluster";
		CFSecClusterPKey pkey = schema.getFactoryCluster().newPKey();
		pkey.setRequiredId( schema.nextClusterIdGen() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFSecClusterByUDomNameIdxKey keyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		keyUDomNameIdx.setRequiredFullDomName( Buff.getRequiredFullDomName() );

		CFSecClusterByUDescrIdxKey keyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUDomNameIdx.containsKey( keyUDomNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ClusterUDomNameIdx",
				keyUDomNameIdx );
		}

		if( dictByUDescrIdx.containsKey( keyUDescrIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ClusterUDescrNameIdx",
				keyUDescrIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUDomNameIdx.put( keyUDomNameIdx, Buff );

		dictByUDescrIdx.put( keyUDescrIdx, Buff );

	}

	public CFSecClusterBuff readDerived( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "CFIntRamCluster.readDerived";
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( PKey.getRequiredId() );
		CFSecClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff lockDerived( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "CFIntRamCluster.readDerived";
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( PKey.getRequiredId() );
		CFSecClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamCluster.readAllDerived";
		CFSecClusterBuff[] retList = new CFSecClusterBuff[ dictByPKey.values().size() ];
		Iterator< CFSecClusterBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecClusterBuff readDerivedByUDomNameIdx( CFSecAuthorization Authorization,
		String FullDomName )
	{
		final String S_ProcName = "CFIntRamCluster.readDerivedByUDomNameIdx";
		CFSecClusterByUDomNameIdxKey key = schema.getFactoryCluster().newUDomNameIdxKey();
		key.setRequiredFullDomName( FullDomName );

		CFSecClusterBuff buff;
		if( dictByUDomNameIdx.containsKey( key ) ) {
			buff = dictByUDomNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff readDerivedByUDescrIdx( CFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFIntRamCluster.readDerivedByUDescrIdx";
		CFSecClusterByUDescrIdxKey key = schema.getFactoryCluster().newUDescrIdxKey();
		key.setRequiredDescription( Description );

		CFSecClusterBuff buff;
		if( dictByUDescrIdx.containsKey( key ) ) {
			buff = dictByUDescrIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long Id )
	{
		final String S_ProcName = "CFIntRamCluster.readDerivedByIdIdx() ";
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( Id );

		CFSecClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff readBuff( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "CFIntRamCluster.readBuff";
		CFSecClusterBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a001" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff lockBuff( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecClusterBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a001" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamCluster.readAllBuff";
		CFSecClusterBuff buff;
		ArrayList<CFSecClusterBuff> filteredList = new ArrayList<CFSecClusterBuff>();
		CFSecClusterBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecClusterBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific Cluster buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific Cluster instances in the database accessible for the Authorization.
	 */
	public CFSecClusterBuff[] pageAllBuff( CFSecAuthorization Authorization,
		Long priorId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecClusterBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long Id )
	{
		final String S_ProcName = "CFIntRamCluster.readBuffByIdIdx() ";
		CFSecClusterBuff buff = readDerivedByIdIdx( Authorization,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
			return( (CFSecClusterBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecClusterBuff readBuffByUDomNameIdx( CFSecAuthorization Authorization,
		String FullDomName )
	{
		final String S_ProcName = "CFIntRamCluster.readBuffByUDomNameIdx() ";
		CFSecClusterBuff buff = readDerivedByUDomNameIdx( Authorization,
			FullDomName );
		if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
			return( (CFSecClusterBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecClusterBuff readBuffByUDescrIdx( CFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFIntRamCluster.readBuffByUDescrIdx() ";
		CFSecClusterBuff buff = readDerivedByUDescrIdx( Authorization,
			Description );
		if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
			return( (CFSecClusterBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateCluster( CFSecAuthorization Authorization,
		CFSecClusterBuff Buff )
	{
		CFSecClusterPKey pkey = schema.getFactoryCluster().newPKey();
		pkey.setRequiredId( Buff.getRequiredId() );
		CFSecClusterBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateCluster",
				"Existing record not found",
				"Cluster",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateCluster",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecClusterByUDomNameIdxKey existingKeyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		existingKeyUDomNameIdx.setRequiredFullDomName( existing.getRequiredFullDomName() );

		CFSecClusterByUDomNameIdxKey newKeyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		newKeyUDomNameIdx.setRequiredFullDomName( Buff.getRequiredFullDomName() );

		CFSecClusterByUDescrIdxKey existingKeyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		existingKeyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecClusterByUDescrIdxKey newKeyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		newKeyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Check unique indexes

		if( ! existingKeyUDomNameIdx.equals( newKeyUDomNameIdx ) ) {
			if( dictByUDomNameIdx.containsKey( newKeyUDomNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateCluster",
					"ClusterUDomNameIdx",
					newKeyUDomNameIdx );
			}
		}

		if( ! existingKeyUDescrIdx.equals( newKeyUDescrIdx ) ) {
			if( dictByUDescrIdx.containsKey( newKeyUDescrIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateCluster",
					"ClusterUDescrNameIdx",
					newKeyUDescrIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecClusterPKey, CFSecClusterBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUDomNameIdx.remove( existingKeyUDomNameIdx );
		dictByUDomNameIdx.put( newKeyUDomNameIdx, Buff );

		dictByUDescrIdx.remove( existingKeyUDescrIdx );
		dictByUDescrIdx.put( newKeyUDescrIdx, Buff );

	}

	public void deleteCluster( CFSecAuthorization Authorization,
		CFSecClusterBuff Buff )
	{
		final String S_ProcName = "CFIntRamClusterTable.deleteCluster() ";
		String classCode;
		CFSecClusterPKey pkey = schema.getFactoryCluster().newPKey();
		pkey.setRequiredId( Buff.getRequiredId() );
		CFSecClusterBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteCluster",
				pkey );
		}
		CFSecSecGroupBuff buffDelSecGroupForms;
		CFSecSecGroupBuff arrDelSecGroupForms[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGroupForms = 0; idxDelSecGroupForms < arrDelSecGroupForms.length; idxDelSecGroupForms++ ) {
			buffDelSecGroupForms = arrDelSecGroupForms[idxDelSecGroupForms];
					schema.getTableSecGroupForm().deleteSecGroupFormByGroupIdx( Authorization,
						buffDelSecGroupForms.getRequiredClusterId(),
						buffDelSecGroupForms.getRequiredSecGroupId() );
		}
		CFSecSecGroupBuff buffDelSecGrpIncByGroup;
		CFSecSecGroupBuff arrDelSecGrpIncByGroup[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpIncByGroup = 0; idxDelSecGrpIncByGroup < arrDelSecGrpIncByGroup.length; idxDelSecGrpIncByGroup++ ) {
			buffDelSecGrpIncByGroup = arrDelSecGrpIncByGroup[idxDelSecGrpIncByGroup];
					schema.getTableSecGrpInc().deleteSecGrpIncByIncludeIdx( Authorization,
						buffDelSecGrpIncByGroup.getRequiredClusterId(),
						buffDelSecGrpIncByGroup.getRequiredSecGroupId() );
		}
		CFSecSecGroupBuff buffDelSecGrpMembs;
		CFSecSecGroupBuff arrDelSecGrpMembs[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpMembs = 0; idxDelSecGrpMembs < arrDelSecGrpMembs.length; idxDelSecGrpMembs++ ) {
			buffDelSecGrpMembs = arrDelSecGrpMembs[idxDelSecGrpMembs];
					schema.getTableSecGrpMemb().deleteSecGrpMembByGroupIdx( Authorization,
						buffDelSecGrpMembs.getRequiredClusterId(),
						buffDelSecGrpMembs.getRequiredSecGroupId() );
		}
		CFSecSecGroupBuff buffDelSecGrpIncs;
		CFSecSecGroupBuff arrDelSecGrpIncs[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpIncs = 0; idxDelSecGrpIncs < arrDelSecGrpIncs.length; idxDelSecGrpIncs++ ) {
			buffDelSecGrpIncs = arrDelSecGrpIncs[idxDelSecGrpIncs];
					schema.getTableSecGrpInc().deleteSecGrpIncByGroupIdx( Authorization,
						buffDelSecGrpIncs.getRequiredClusterId(),
						buffDelSecGrpIncs.getRequiredSecGroupId() );
		}
					schema.getTableSecGroup().deleteSecGroupByClusterIdx( Authorization,
						existing.getRequiredId() );
		CFSecSecAppBuff buffDelSecAppForms;
		CFSecSecAppBuff arrDelSecAppForms[] = schema.getTableSecApp().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecAppForms = 0; idxDelSecAppForms < arrDelSecAppForms.length; idxDelSecAppForms++ ) {
			buffDelSecAppForms = arrDelSecAppForms[idxDelSecAppForms];
					schema.getTableSecForm().deleteSecFormBySecAppIdx( Authorization,
						buffDelSecAppForms.getRequiredClusterId(),
						buffDelSecAppForms.getRequiredSecAppId() );
		}
					schema.getTableSecApp().deleteSecAppByClusterIdx( Authorization,
						existing.getRequiredId() );
					schema.getTableTenant().deleteTenantByClusterIdx( Authorization,
						existing.getRequiredId() );
					schema.getTableHostNode().deleteHostNodeByClusterIdx( Authorization,
						existing.getRequiredId() );
		CFSecClusterByUDomNameIdxKey keyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		keyUDomNameIdx.setRequiredFullDomName( existing.getRequiredFullDomName() );

		CFSecClusterByUDescrIdxKey keyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecClusterPKey, CFSecClusterBuff > subdict;

		dictByPKey.remove( pkey );

		dictByUDomNameIdx.remove( keyUDomNameIdx );

		dictByUDescrIdx.remove( keyUDescrIdx );

	}
	public void deleteClusterByIdIdx( CFSecAuthorization Authorization,
		long argId )
	{
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( argId );
		deleteClusterByIdIdx( Authorization, key );
	}

	public void deleteClusterByIdIdx( CFSecAuthorization Authorization,
		CFSecClusterPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecClusterBuff cur;
		LinkedList<CFSecClusterBuff> matchSet = new LinkedList<CFSecClusterBuff>();
		Iterator<CFSecClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() );
			deleteCluster( Authorization, cur );
		}
	}

	public void deleteClusterByUDomNameIdx( CFSecAuthorization Authorization,
		String argFullDomName )
	{
		CFSecClusterByUDomNameIdxKey key = schema.getFactoryCluster().newUDomNameIdxKey();
		key.setRequiredFullDomName( argFullDomName );
		deleteClusterByUDomNameIdx( Authorization, key );
	}

	public void deleteClusterByUDomNameIdx( CFSecAuthorization Authorization,
		CFSecClusterByUDomNameIdxKey argKey )
	{
		CFSecClusterBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecClusterBuff> matchSet = new LinkedList<CFSecClusterBuff>();
		Iterator<CFSecClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() );
			deleteCluster( Authorization, cur );
		}
	}

	public void deleteClusterByUDescrIdx( CFSecAuthorization Authorization,
		String argDescription )
	{
		CFSecClusterByUDescrIdxKey key = schema.getFactoryCluster().newUDescrIdxKey();
		key.setRequiredDescription( argDescription );
		deleteClusterByUDescrIdx( Authorization, key );
	}

	public void deleteClusterByUDescrIdx( CFSecAuthorization Authorization,
		CFSecClusterByUDescrIdxKey argKey )
	{
		CFSecClusterBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecClusterBuff> matchSet = new LinkedList<CFSecClusterBuff>();
		Iterator<CFSecClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() );
			deleteCluster( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
